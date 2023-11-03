package commons

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	spectypes "github.com/bloxapp/ssv-spec/types"
	"github.com/cespare/xxhash/v2"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.uber.org/zap"

	p2pprotocol "github.com/bloxapp/ssv/protocol/v2/p2p"
)

const (
	lastDecidedProtocol = "/ssv/sync/decided/last/0.0.1"
	historyProtocol     = "/ssv/sync/decided/history/0.0.1"

	peersForSync = 10

	// subnetsCount returns the subnet count for genesis
	subnetsCount uint64 = 128

	// UnknownSubnet is used when a validator public key is invalid
	UnknownSubnet = "unknown"

	topicPrefix = "ssv.v2"
)

const (
	signatureSize    = 256
	signatureOffset  = 0
	operatorIDSize   = 8
	operatorIDOffset = signatureOffset + signatureSize
	messageOffset    = operatorIDOffset + operatorIDSize
)

func EncodeSignedSSVMessage(message []byte, operatorID spectypes.OperatorID, signature []byte) []byte {
	return append(append(signature, binary.LittleEndian.AppendUint64(nil, operatorID)...), message...)
}

func DecodeSignedSSVMessage(encoded []byte) (message []byte, operatorID spectypes.OperatorID, signature []byte, err error) {
	if len(encoded) < messageOffset {
		err = fmt.Errorf("unexpected encoded message size of %d", len(encoded))
		return
	}

	message = encoded[messageOffset:]
	operatorID = binary.LittleEndian.Uint64(encoded[operatorIDOffset : operatorIDOffset+operatorIDSize])
	signature = encoded[signatureOffset : signatureOffset+signatureSize]
	return
}

// SubnetTopicID returns the topic to use for the given subnet
func SubnetTopicID(subnet int) string {
	if subnet < 0 {
		return UnknownSubnet
	}
	return fmt.Sprintf("%d", subnet)
}

// ValidatorTopicID returns the topic to use for the given validator
func ValidatorTopicID(pkByts []byte) []string {
	pkHex := hex.EncodeToString(pkByts)
	subnet := ValidatorSubnet(pkHex)
	return []string{SubnetTopicID(subnet)}
}

// GetTopicFullName returns the topic full name, including prefix
func GetTopicFullName(baseName string) string {
	return fmt.Sprintf("%s.%s", topicPrefix, baseName)
}

// GetTopicBaseName return the base topic name of the topic, w/o ssv prefix
func GetTopicBaseName(topicName string) string {
	return strings.Replace(topicName, fmt.Sprintf("%s.", topicPrefix), "", 1)
}

// ValidatorSubnet returns the subnet for the given validator
func ValidatorSubnet(validatorPKHex string) int {
	if len(validatorPKHex) < 10 {
		return -1
	}
	val := hexToUint64(validatorPKHex[:10])
	return int(val % subnetsCount)
}

// MsgIDFunc is the function that maps a message to a msg_id
type MsgIDFunc func(msg []byte) string

var metricMsgIDCalls = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "ssv_msg_id_calls",
	Help: "",
}, []string{"with_signature"})

func init() {
	if err := prometheus.Register(metricMsgIDCalls); err != nil {
		zap.L().Debug("could not register prometheus collector")
	}
}

// MsgID returns msg_id for the given message
func MsgID() MsgIDFunc {
	return func(msg []byte) string {
		if len(msg) == 0 {
			return ""
		}

		//message, _, _, err := DecodeSignedSSVMessage(msg)
		//if err != nil {
		//	metricMsgIDCalls.WithLabelValues("NotDecoded").Inc()
		//} else {
		//	metricMsgIDCalls.WithLabelValues("Decoded").Inc()
		//	msg = message
		//}

		b := make([]byte, 12)
		binary.LittleEndian.PutUint64(b, xxhash.Sum64(msg))
		return string(b)
	}
}

// Subnets returns the subnets count for this fork
func Subnets() int {
	return int(subnetsCount)
}

// Topics returns the available topics for this fork.
func Topics() []string {
	topics := make([]string, Subnets())
	for i := 0; i < Subnets(); i++ {
		topics[i] = GetTopicFullName(SubnetTopicID(i))
	}
	return topics
}

// AddOptions implementation
func AddOptions(opts []libp2p.Option) []libp2p.Option {
	opts = append(opts, libp2p.Ping(true))
	opts = append(opts, libp2p.EnableNATService())
	opts = append(opts, libp2p.AutoNATServiceRateLimit(15, 3, 1*time.Minute))
	// opts = append(opts, libp2p.DisableRelay())
	return opts
}

type EncryptedSSVMessage struct {
	SSVMessage *spectypes.SSVMessage
	Signature  []byte
}

// EncodeNetworkMsg encodes network message
func EncodeNetworkMsg(msg *spectypes.SSVMessage) ([]byte, error) {
	return msg.Encode()
}

// DecodeNetworkMsg decodes network message
func DecodeNetworkMsg(data []byte) (*spectypes.SSVMessage, error) {
	msg := spectypes.SSVMessage{}
	err := msg.Decode(data)
	if err != nil {
		return nil, err
	}
	return &msg, nil
}

// ProtocolID returns the protocol id of the given protocol,
// and the amount of peers for distribution
func ProtocolID(prot p2pprotocol.SyncProtocol) (protocol.ID, int) {
	switch prot {
	case p2pprotocol.LastDecidedProtocol:
		return lastDecidedProtocol, peersForSync
	case p2pprotocol.DecidedHistoryProtocol:
		return historyProtocol, peersForSync
	}
	return "", 0
}

func hexToUint64(hexStr string) uint64 {
	result, err := strconv.ParseUint(hexStr, 16, 64)
	if err != nil {
		return uint64(0)
	}
	return result
}
