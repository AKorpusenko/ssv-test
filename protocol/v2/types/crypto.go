package types

import (
	"encoding/hex"
	"sync"
	"time"

	specssv "github.com/bloxapp/ssv-spec/ssv"
	spectypes "github.com/bloxapp/ssv-spec/types"
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/exp/maps"
)

var Verifier = NewBatchVerifier(4, 2, time.Millisecond*5)

func init() {
	go Verifier.Start()
}

// VerifyByOperators verifies signature by the provided operators
// This is a copy of a function with the same name from the spec, except for it's use of
// DeserializeBLSPublicKey function and bounded.CGO
//
// TODO: rethink this function and consider moving/refactoring it.
func VerifyByOperators(s spectypes.Signature, data spectypes.MessageSignature, domain spectypes.DomainType, sigType spectypes.SignatureType, operators []*spectypes.Operator) error {
	// decode sig
	sign := &bls.Sign{}
	if err := sign.Deserialize(s); err != nil {
		return errors.Wrap(err, "failed to deserialize signature")
	}

	// find operators
	pks := make([]bls.PublicKey, 0)
	for _, id := range data.GetSigners() {
		found := false
		for _, n := range operators {
			if id == n.GetID() {
				pk, err := DeserializeBLSPublicKey(n.GetPublicKey())
				if err != nil {
					return errors.Wrap(err, "failed to deserialize public key")
				}

				pks = append(pks, pk)
				found = true
			}
		}
		if !found {
			return errors.New("unknown signer")
		}
	}

	// compute root
	computedRoot, err := spectypes.ComputeSigningRoot(data, spectypes.ComputeSignatureDomain(domain, sigType))
	if err != nil {
		return errors.Wrap(err, "could not compute signing root")
	}

	// verify
	// if res := sign.FastAggregateVerify(pks, computedRoot[:]); !res {
	// 	return errors.New("failed to verify signature")
	// }
	if res := Verifier.AggregateVerify(sign, pks, computedRoot); !res {
		return errors.New("failed to verify signature")
	}
	return nil
}

func ReconstructSignature(ps *specssv.PartialSigContainer, root [32]byte, validatorPubKey []byte) ([]byte, error) {
	// Reconstruct signatures
	signature, err := spectypes.ReconstructSignatures(ps.Signatures[rootHex(root)])
	if err != nil {
		return nil, errors.Wrap(err, "failed to reconstruct signatures")
	}
	if err := VerifyReconstructedSignature(signature, validatorPubKey, root); err != nil {
		return nil, errors.Wrap(err, "failed to verify reconstruct signature")
	}
	return signature.Serialize(), nil
}

func VerifyReconstructedSignature(sig *bls.Sign, validatorPubKey []byte, root [32]byte) error {
	pk, err := DeserializeBLSPublicKey(validatorPubKey)
	if err != nil {
		return errors.Wrap(err, "could not deserialize validator pk")
	}

	// verify reconstructed sig
	if res := sig.VerifyByte(&pk, root[:]); !res {
		return errors.New("could not reconstruct a valid signature")
	}
	return nil
}

func rootHex(r [32]byte) string {
	return hex.EncodeToString(r[:])
}

const messageSize = 32

type SignatureRequest struct {
	Signature *bls.Sign
	PubKeys   []bls.PublicKey
	Message   [messageSize]byte
	Result    chan bool
}

type BatchVerifier struct {
	workers   int
	batchSize int
	timeout   time.Duration

	ticker  *time.Ticker
	pending map[[messageSize]byte]*SignatureRequest
	mu      sync.Mutex

	batches chan []*SignatureRequest

	debug struct {
		lens [20]int
		n    int
		mu   sync.Mutex
	}
}

func NewBatchVerifier(workers, batchSize int, timeout time.Duration) *BatchVerifier {
	return &BatchVerifier{
		workers:   workers,
		batchSize: batchSize,
		timeout:   timeout,
		pending:   make(map[[messageSize]byte]*SignatureRequest),
		batches:   make(chan []*SignatureRequest, workers*2),
	}
}

func (b *BatchVerifier) AggregateVerify(signature *bls.Sign, pks []bls.PublicKey, message [messageSize]byte) bool {
	sr := &SignatureRequest{
		Signature: signature,
		PubKeys:   pks,
		Message:   message,
		Result:    make(chan bool),
	}

	b.mu.Lock()
	if _, exists := b.pending[message]; exists {
		b.mu.Unlock()
		return signature.FastAggregateVerify(pks, message[:])
	}

	b.pending[message] = sr
	if len(b.pending) == b.batchSize {
		batch := b.pending
		b.pending = make(map[[messageSize]byte]*SignatureRequest)
		b.mu.Unlock()

		b.batches <- maps.Values(batch)
	} else {
		b.mu.Unlock()
	}

	return <-sr.Result
}

func (b *BatchVerifier) Start() {
	b.ticker = time.NewTicker(b.timeout)
	for i := 0; i < b.workers; i++ {
		go b.worker()
	}
}

func (b *BatchVerifier) worker() {
	for {
		select {
		case batch := <-b.batches:
			b.verify(batch)
		case <-b.ticker.C:
			b.mu.Lock()
			batch := b.pending
			b.pending = make(map[[messageSize]byte]*SignatureRequest)
			b.mu.Unlock()

			if len(batch) > 0 {
				b.verify(maps.Values(batch))
			}
		}
	}
}

func (b *BatchVerifier) verify(batch []*SignatureRequest) {
	b.debug.mu.Lock()
	b.debug.n++
	b.debug.lens[b.debug.n%20] = len(batch)
	if b.debug.n%20 == 0 {
		zap.L().Info("verifying batch", zap.Ints("sizes", b.debug.lens[:]))
	}
	b.debug.mu.Unlock()

	if len(batch) == 1 {
		b.verifySingle(batch[0])
		return
	}

	sig := *batch[0].Signature
	pks := make([]bls.PublicKey, len(batch))
	msgs := make([]byte, len(batch)*messageSize)
	for i, req := range batch {
		if i > 0 {
			sig.Add(req.Signature)
		}

		// Aggregate public keys.
		pk := req.PubKeys[0]
		for j := 1; j < len(req.PubKeys); j++ {
			pk.Add(&req.PubKeys[j])
		}
		pks[i] = pk

		copy(msgs[messageSize*i:], req.Message[:])
	}
	if sig.AggregateVerify(pks, msgs) {
		for _, req := range batch {
			req.Result <- true
		}
	} else {
		// Fallback to individual verification.
		for _, req := range batch {
			b.verifySingle(req)
		}
	}
}

func (b *BatchVerifier) verifySingle(req *SignatureRequest) {
	msg := req.Message
	req.Result <- req.Signature.FastAggregateVerify(req.PubKeys, msg[:])
}
