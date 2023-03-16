package runner

import (
	"crypto/sha256"
	"encoding/json"

	"github.com/attestantio/go-eth2-client/api"
	apiv1bellatrix "github.com/attestantio/go-eth2-client/api/v1/bellatrix"
	apiv1capella "github.com/attestantio/go-eth2-client/api/v1/capella"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	specqbft "github.com/bloxapp/ssv-spec/qbft"
	specssv "github.com/bloxapp/ssv-spec/ssv"
	spectypes "github.com/bloxapp/ssv-spec/types"
	ssz "github.com/ferranbt/fastssz"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/attestantio/go-eth2-client/spec"

	"github.com/bloxapp/ssv/protocol/v2/qbft/controller"
	"github.com/bloxapp/ssv/protocol/v2/ssv/runner/metrics"
)

type ProposerRunner struct {
	BaseRunner *BaseRunner
	// ProducesBlindedBlocks is true when the runner will only produce blinded blocks
	ProducesBlindedBlocks bool

	beacon   specssv.BeaconNode
	network  specssv.Network
	signer   spectypes.KeyManager
	valCheck specqbft.ProposedValueCheckF

	metrics metrics.ConsensusMetrics
}

func NewProposerRunner(
	beaconNetwork spectypes.BeaconNetwork,
	share *spectypes.Share,
	qbftController *controller.Controller,
	beacon specssv.BeaconNode,
	network specssv.Network,
	signer spectypes.KeyManager,
	valCheck specqbft.ProposedValueCheckF,
) Runner {
	return &ProposerRunner{
		BaseRunner: &BaseRunner{
			BeaconRoleType: spectypes.BNRoleProposer,
			BeaconNetwork:  beaconNetwork,
			Share:          share,
			QBFTController: qbftController,
		},

		beacon:   beacon,
		network:  network,
		signer:   signer,
		valCheck: valCheck,
		metrics:  metrics.NewConsensusMetrics(share.ValidatorPubKey, spectypes.BNRoleProposer),
	}
}

func (r *ProposerRunner) StartNewDuty(logger *zap.Logger, duty *spectypes.Duty) error {
	return r.BaseRunner.baseStartNewDuty(logger, r, duty)
}

// HasRunningDuty returns true if a duty is already running (StartNewDuty called and returned nil)
func (r *ProposerRunner) HasRunningDuty() bool {
	return r.BaseRunner.hasRunningDuty()
}

func (r *ProposerRunner) ProcessPreConsensus(logger *zap.Logger, signedMsg *spectypes.SignedPartialSignatureMessage) error {
	quorum, roots, err := r.BaseRunner.basePreConsensusMsgProcessing(r, signedMsg)
	if err != nil {
		return errors.Wrap(err, "failed processing randao message")
	}

	// quorum returns true only once (first time quorum achieved)
	if !quorum {
		return nil
	}

	r.metrics.EndPreConsensus()

	// only 1 root, verified in basePreConsensusMsgProcessing
	root := roots[0]
	// randao is relevant only for block proposals, no need to check type
	fullSig, err := r.GetState().ReconstructBeaconSig(r.GetState().PreConsensusContainer, root, r.GetShare().ValidatorPubKey)
	if err != nil {
		return errors.Wrap(err, "could not reconstruct randao sig")
	}

	duty := r.GetState().StartingDuty

	var ver spec.DataVersion
	var obj ssz.Marshaler
	if r.ProducesBlindedBlocks {
		// get block data
		obj, ver, err = r.GetBeaconNode().GetBlindedBeaconBlock(duty.Slot, duty.CommitteeIndex, r.GetShare().Graffiti, fullSig)
		if err != nil {
			return errors.Wrap(err, "failed to get Beacon block")
		}
	} else {
		// get block data
		obj, ver, err = r.GetBeaconNode().GetBeaconBlock(duty.Slot, duty.CommitteeIndex, r.GetShare().Graffiti, fullSig)
		if err != nil {
			return errors.Wrap(err, "failed to get Beacon block")
		}
	}

	byts, err := obj.MarshalSSZ()
	if err != nil {
		return errors.Wrap(err, "could not marshal beacon block")
	}

	input := &spectypes.ConsensusData{
		Duty:    *duty,
		Version: ver,
		DataSSZ: byts,
	}

	r.metrics.StartConsensus()
	if err := r.BaseRunner.decide(logger, r, input); err != nil {
		return errors.Wrap(err, "can't start new duty runner instance for duty")
	}

	return nil
}

func (r *ProposerRunner) ProcessConsensus(logger *zap.Logger, signedMsg *specqbft.SignedMessage) error {
	decided, decidedValue, err := r.BaseRunner.baseConsensusMsgProcessing(logger, r, signedMsg)
	if err != nil {
		return errors.Wrap(err, "failed processing consensus message")
	}

	// Decided returns true only once so if it is true it must be for the current running instance
	if !decided {
		return nil
	}

	r.metrics.EndConsensus()
	r.metrics.StartPostConsensus()

	// specific duty sig
	var blkToSign ssz.HashRoot
	if r.decidedBlindedBlock() {
		_, blkToSign, err = decidedValue.GetBlindedBlockData()
		if err != nil {
			return errors.Wrap(err, "could not get blinded block data")
		}
	} else {
		_, blkToSign, err = decidedValue.GetBlockData()
		if err != nil {
			return errors.Wrap(err, "could not get block data")
		}
	}
	if err != nil {
		return errors.Wrap(err, "could not get block")
	}

	msg, err := r.BaseRunner.signBeaconObject(
		r,
		blkToSign,
		decidedValue.Duty.Slot,
		spectypes.DomainProposer,
	)
	if err != nil {
		return errors.Wrap(err, "failed signing attestation data")
	}
	postConsensusMsg := &spectypes.PartialSignatureMessages{
		Type:     spectypes.PostConsensusPartialSig,
		Slot:     decidedValue.Duty.Slot,
		Messages: []*spectypes.PartialSignatureMessage{msg},
	}

	postSignedMsg, err := r.BaseRunner.signPostConsensusMsg(r, postConsensusMsg)
	if err != nil {
		return errors.Wrap(err, "could not sign post consensus msg")
	}

	data, err := postSignedMsg.Encode()
	if err != nil {
		return errors.Wrap(err, "failed to encode post consensus signature msg")
	}

	msgToBroadcast := &spectypes.SSVMessage{
		MsgType: spectypes.SSVPartialSignatureMsgType,
		MsgID:   spectypes.NewMsgID(r.GetShare().DomainType, r.GetShare().ValidatorPubKey, r.BaseRunner.BeaconRoleType),
		Data:    data,
	}

	if err := r.GetNetwork().Broadcast(msgToBroadcast); err != nil {
		return errors.Wrap(err, "can't broadcast partial post consensus sig")
	}
	return nil
}

func (r *ProposerRunner) ProcessPostConsensus(logger *zap.Logger, signedMsg *spectypes.SignedPartialSignatureMessage) error {
	quorum, roots, err := r.BaseRunner.basePostConsensusMsgProcessing(logger, r, signedMsg)
	if err != nil {
		return errors.Wrap(err, "failed processing post consensus message")
	}

	if !quorum {
		return nil
	}

	r.metrics.EndPostConsensus()

	for _, root := range roots {
		sig, err := r.GetState().ReconstructBeaconSig(r.GetState().PostConsensusContainer, root, r.GetShare().ValidatorPubKey)
		if err != nil {
			return errors.Wrap(err, "could not reconstruct post consensus signature")
		}
		specSig := phase0.BLSSignature{}
		copy(specSig[:], sig)

		blockSubmissionEnd := r.metrics.StartBeaconSubmission()

		if r.decidedBlindedBlock() {
			vBlindedBlk, _, err := r.GetState().DecidedValue.GetBlindedBlockData()
			if err != nil {
				return errors.Wrap(err, "could not get blinded block")
			}

			var blkToSubmit *api.VersionedSignedBlindedBeaconBlock
			switch vBlindedBlk.Version {
			case spec.DataVersionBellatrix:
				if vBlindedBlk.Bellatrix == nil {
					return errors.New("bellatrix blinded block is nil")
				}
				blkToSubmit = &api.VersionedSignedBlindedBeaconBlock{
					Version: spec.DataVersionBellatrix,
					Bellatrix: &apiv1bellatrix.SignedBlindedBeaconBlock{
						Message: vBlindedBlk.Bellatrix,
					},
				}
				copy(blkToSubmit.Bellatrix.Signature[:], specSig[:])
			case spec.DataVersionCapella:
				if vBlindedBlk.Capella == nil {
					return errors.New("capella blinded block is nil")
				}
				blkToSubmit = &api.VersionedSignedBlindedBeaconBlock{
					Version: spec.DataVersionCapella,
					Capella: &apiv1capella.SignedBlindedBeaconBlock{
						Message: vBlindedBlk.Capella,
					},
				}
				copy(blkToSubmit.Capella.Signature[:], specSig[:])
			default:
				return errors.New("unknown blinded block version")
			}

			if err := r.GetBeaconNode().SubmitBlindedBeaconBlock(blkToSubmit); err != nil {
				return errors.Wrap(err, "could not submit to Beacon chain reconstructed signed blinded Beacon block")
			}
		} else {
			vBlk, _, err := r.GetState().DecidedValue.GetBlockData()
			if err != nil {
				return errors.Wrap(err, "could not get block")
			}

			var blkToSubmit *spec.VersionedSignedBeaconBlock
			switch vBlk.Version {
			case spec.DataVersionPhase0:
				if vBlk.Phase0 == nil {
					return errors.New("phase0 block is nil")
				}
				blkToSubmit = &spec.VersionedSignedBeaconBlock{
					Version: spec.DataVersionPhase0,
					Phase0: &phase0.SignedBeaconBlock{
						Message: vBlk.Phase0,
					},
				}
				copy(blkToSubmit.Phase0.Signature[:], specSig[:])
			case spec.DataVersionAltair:
				if vBlk.Altair == nil {
					return errors.New("altair block is nil")
				}
				blkToSubmit = &spec.VersionedSignedBeaconBlock{
					Version: spec.DataVersionAltair,
					Altair: &altair.SignedBeaconBlock{
						Message: vBlk.Altair,
					},
				}
				copy(blkToSubmit.Altair.Signature[:], specSig[:])
			case spec.DataVersionBellatrix:
				if vBlk.Bellatrix == nil {
					return errors.New("bellatrix block is nil")
				}
				blkToSubmit = &spec.VersionedSignedBeaconBlock{
					Version: spec.DataVersionBellatrix,
					Bellatrix: &bellatrix.SignedBeaconBlock{
						Message: vBlk.Bellatrix,
					},
				}
				copy(blkToSubmit.Bellatrix.Signature[:], specSig[:])
			case spec.DataVersionCapella:
				if vBlk.Capella == nil {
					return errors.New("capella block is nil")
				}
				blkToSubmit = &spec.VersionedSignedBeaconBlock{
					Version: spec.DataVersionCapella,
					Capella: &capella.SignedBeaconBlock{
						Message: vBlk.Capella,
					},
				}
				copy(blkToSubmit.Capella.Signature[:], specSig[:])
			default:
				return errors.New("unknown block version")
			}

			if err := r.GetBeaconNode().SubmitBeaconBlock(blkToSubmit); err != nil {
				r.metrics.RoleSubmissionFailed()
				return errors.Wrap(err, "could not submit to Beacon chain reconstructed signed Beacon block")
			}
		}

		blockSubmissionEnd()
		r.metrics.EndDutyFullFlow()
		r.metrics.RoleSubmitted()

		logger.Info("✅ successfully proposed block!")
	}

	r.GetState().Finished = true

	return nil
}

// decidedBlindedBlock returns true if decided value has a blinded block, false if regular block
// WARNING!! should be called after decided only
func (r *ProposerRunner) decidedBlindedBlock() bool {
	_, _, err := r.BaseRunner.State.DecidedValue.GetBlindedBlockData()
	return err == nil
}

func (r *ProposerRunner) expectedPreConsensusRootsAndDomain() ([]ssz.HashRoot, phase0.DomainType, error) {
	epoch := r.BaseRunner.BeaconNetwork.EstimatedEpochAtSlot(r.GetState().StartingDuty.Slot)
	return []ssz.HashRoot{spectypes.SSZUint64(epoch)}, spectypes.DomainRandao, nil
}

// expectedPostConsensusRootsAndDomain an INTERNAL function, returns the expected post-consensus roots to sign
func (r *ProposerRunner) expectedPostConsensusRootsAndDomain() ([]ssz.HashRoot, phase0.DomainType, error) {
	if r.decidedBlindedBlock() {
		_, data, err := r.GetState().DecidedValue.GetBlindedBlockData()
		if err != nil {
			return nil, phase0.DomainType{}, errors.Wrap(err, "could not get blinded block data")
		}
		return []ssz.HashRoot{data}, spectypes.DomainProposer, nil
	}

	_, data, err := r.GetState().DecidedValue.GetBlockData()
	if err != nil {
		return nil, phase0.DomainType{}, errors.Wrap(err, "could not get block data")
	}
	return []ssz.HashRoot{data}, spectypes.DomainProposer, nil
}

// executeDuty steps:
// 1) sign a partial randao sig and wait for 2f+1 partial sigs from peers
// 2) reconstruct randao and send GetBeaconBlock to BN
// 3) start consensus on duty + block data
// 4) Once consensus decides, sign partial block and broadcast
// 5) collect 2f+1 partial sigs, reconstruct and broadcast valid block sig to the BN
func (r *ProposerRunner) executeDuty(logger *zap.Logger, duty *spectypes.Duty) error {
	r.metrics.StartDutyFullFlow()
	r.metrics.StartPreConsensus()

	// sign partial randao
	epoch := r.GetBeaconNode().GetBeaconNetwork().EstimatedEpochAtSlot(duty.Slot)
	msg, err := r.BaseRunner.signBeaconObject(r, spectypes.SSZUint64(epoch), duty.Slot, spectypes.DomainRandao)
	if err != nil {
		return errors.Wrap(err, "could not sign randao")
	}
	msgs := spectypes.PartialSignatureMessages{
		Type:     spectypes.RandaoPartialSig,
		Slot:     duty.Slot,
		Messages: []*spectypes.PartialSignatureMessage{msg},
	}

	// sign msg
	signature, err := r.GetSigner().SignRoot(msgs, spectypes.PartialSignatureType, r.GetShare().SharePubKey)
	if err != nil {
		return errors.Wrap(err, "could not sign randao msg")
	}
	signedPartialMsg := &spectypes.SignedPartialSignatureMessage{
		Message:   msgs,
		Signature: signature,
		Signer:    r.GetShare().OperatorID,
	}

	// broadcast
	data, err := signedPartialMsg.Encode()
	if err != nil {
		return errors.Wrap(err, "failed to encode randao pre-consensus signature msg")
	}
	msgToBroadcast := &spectypes.SSVMessage{
		MsgType: spectypes.SSVPartialSignatureMsgType,
		MsgID:   spectypes.NewMsgID(r.GetShare().DomainType, r.GetShare().ValidatorPubKey, r.BaseRunner.BeaconRoleType),
		Data:    data,
	}
	if err := r.GetNetwork().Broadcast(msgToBroadcast); err != nil {
		return errors.Wrap(err, "can't broadcast partial randao sig")
	}
	return nil
}

func (r *ProposerRunner) GetBaseRunner() *BaseRunner {
	return r.BaseRunner
}

func (r *ProposerRunner) GetNetwork() specssv.Network {
	return r.network
}

func (r *ProposerRunner) GetBeaconNode() specssv.BeaconNode {
	return r.beacon
}

func (r *ProposerRunner) GetShare() *spectypes.Share {
	return r.BaseRunner.Share
}

func (r *ProposerRunner) GetState() *State {
	return r.BaseRunner.State
}

func (r *ProposerRunner) GetValCheckF() specqbft.ProposedValueCheckF {
	return r.valCheck
}

func (r *ProposerRunner) GetSigner() spectypes.KeyManager {
	return r.signer
}

// Encode returns the encoded struct in bytes or error
func (r *ProposerRunner) Encode() ([]byte, error) {
	return json.Marshal(r)
}

// Decode returns error if decoding failed
func (r *ProposerRunner) Decode(data []byte) error {
	return json.Unmarshal(data, &r)
}

// GetRoot returns the root used for signing and verification
func (r *ProposerRunner) GetRoot() ([32]byte, error) {
	marshaledRoot, err := r.Encode()
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "could not encode DutyRunnerState")
	}
	ret := sha256.Sum256(marshaledRoot)
	return ret, nil
}
