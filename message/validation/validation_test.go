package validation

import (
	"bytes"
	"encoding/hex"
	"math"
	"testing"
	"time"

	v1 "github.com/attestantio/go-eth2-client/api/v1"
	specqbft "github.com/bloxapp/ssv-spec/qbft"
	spectypes "github.com/bloxapp/ssv-spec/types"
	spectestingutils "github.com/bloxapp/ssv-spec/types/testingutils"
	ssz "github.com/ferranbt/fastssz"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/bloxapp/ssv/networkconfig"
	"github.com/bloxapp/ssv/operator/storage"
	beaconprotocol "github.com/bloxapp/ssv/protocol/v2/blockchain/beacon"
	"github.com/bloxapp/ssv/protocol/v2/ssv/queue"
	ssvtypes "github.com/bloxapp/ssv/protocol/v2/types"
	ssvstorage "github.com/bloxapp/ssv/storage"
	"github.com/bloxapp/ssv/storage/basedb"
)

func Test_Validation(t *testing.T) {
	logger := zaptest.NewLogger(t)
	db, err := ssvstorage.GetStorageFactory(logger, basedb.Options{
		Type: "badger-memory",
		Path: "",
	})
	require.NoError(t, err)

	ns, err := storage.NewNodeStorage(logger, db)
	require.NoError(t, err)

	ks := spectestingutils.Testing4SharesSet()
	share := &ssvtypes.SSVShare{
		Share: *spectestingutils.TestingShare(ks),
		Metadata: ssvtypes.Metadata{
			BeaconMetadata: &beaconprotocol.ValidatorMetadata{
				Status: v1.ValidatorStateActiveOngoing,
			},
			Liquidated: false,
		},
	}
	require.NoError(t, ns.Shares().Save(share))

	netCfg := networkconfig.TestNetwork

	roleAttester := spectypes.BNRoleAttester

	t.Run("happy flow", func(t *testing.T) {
		validator := NewMessageValidator(netCfg, ns.Shares())

		slot := netCfg.Beacon.FirstSlotAtEpoch(1)
		height := specqbft.Height(slot)

		validSignedMessage := spectestingutils.TestingProposalMessageWithHeight(ks.Shares[1], 1, height)
		encodedValidSignedMessage, err := validSignedMessage.Encode()
		require.NoError(t, err)

		message := &spectypes.SSVMessage{
			MsgType: spectypes.SSVConsensusMsgType,
			MsgID:   spectypes.NewMsgID(netCfg.Domain, share.ValidatorPubKey, roleAttester),
			Data:    encodedValidSignedMessage,
		}

		receivedAt := netCfg.Beacon.GetSlotStartTime(slot).Add(validator.waitAfterSlotStart(roleAttester))
		_, err = validator.ValidateMessage(message, receivedAt)
		require.NoError(t, err)
	})

	t.Run("no data", func(t *testing.T) {
		validator := NewMessageValidator(netCfg, ns.Shares())

		message := &spectypes.SSVMessage{
			MsgType: spectypes.SSVConsensusMsgType,
			MsgID:   spectypes.NewMsgID(netCfg.Domain, share.ValidatorPubKey, roleAttester),
			Data:    []byte{},
		}

		_, err := validator.ValidateMessage(message, time.Now())
		require.ErrorIs(t, err, ErrEmptyData)

		message = &spectypes.SSVMessage{
			MsgType: spectypes.SSVConsensusMsgType,
			MsgID:   spectypes.NewMsgID(netCfg.Domain, share.ValidatorPubKey, roleAttester),
			Data:    nil,
		}

		_, err = validator.ValidateMessage(message, time.Now())
		require.ErrorIs(t, err, ErrEmptyData)
	})

	t.Run("data too big", func(t *testing.T) {
		validator := NewMessageValidator(netCfg, ns.Shares())

		const tooBigMsgSize = maxMessageSize * 2

		message := &spectypes.SSVMessage{
			MsgType: spectypes.SSVConsensusMsgType,
			MsgID:   spectypes.NewMsgID(netCfg.Domain, share.ValidatorPubKey, roleAttester),
			Data:    bytes.Repeat([]byte{0x1}, tooBigMsgSize),
		}

		_, err := validator.ValidateMessage(message, time.Now())
		expectedErr := ErrDataTooBig
		expectedErr.got = tooBigMsgSize
		require.ErrorIs(t, err, expectedErr)
	})

	t.Run("data size borderline / malformed message", func(t *testing.T) {
		validator := NewMessageValidator(netCfg, ns.Shares())

		message := &spectypes.SSVMessage{
			MsgType: spectypes.SSVConsensusMsgType,
			MsgID:   spectypes.NewMsgID(netCfg.Domain, share.ValidatorPubKey, roleAttester),
			Data:    bytes.Repeat([]byte{0x1}, maxMessageSize),
		}

		_, err := validator.ValidateMessage(message, time.Now())
		require.ErrorIs(t, err, ssz.ErrOffset)
	})

	t.Run("invalid SSV message type", func(t *testing.T) {
		validator := NewMessageValidator(netCfg, ns.Shares())

		message := &spectypes.SSVMessage{
			MsgType: math.MaxUint64,
			MsgID:   spectypes.NewMsgID(netCfg.Domain, share.ValidatorPubKey, roleAttester),
			Data:    []byte{0x1},
		}

		_, err = validator.ValidateMessage(message, time.Now())
		require.ErrorIs(t, err, queue.ErrUnknownMessageType)
	})

	t.Run("wrong domain", func(t *testing.T) {
		validator := NewMessageValidator(netCfg, ns.Shares())

		slot := netCfg.Beacon.FirstSlotAtEpoch(1)
		height := specqbft.Height(slot)

		validSignedMessage := spectestingutils.TestingProposalMessageWithHeight(ks.Shares[1], 1, height)
		encodedValidSignedMessage, err := validSignedMessage.Encode()
		require.NoError(t, err)

		wrongDomain := spectypes.DomainType{math.MaxUint8, math.MaxUint8, math.MaxUint8, math.MaxUint8}
		message := &spectypes.SSVMessage{
			MsgType: spectypes.SSVConsensusMsgType,
			MsgID:   spectypes.NewMsgID(wrongDomain, share.ValidatorPubKey, roleAttester),
			Data:    encodedValidSignedMessage,
		}

		receivedAt := netCfg.Beacon.GetSlotStartTime(slot).Add(validator.waitAfterSlotStart(roleAttester))
		_, err = validator.ValidateMessage(message, receivedAt)
		expectedErr := ErrWrongDomain
		expectedErr.got = hex.EncodeToString(wrongDomain[:])
		expectedErr.want = hex.EncodeToString(netCfg.Domain[:])
		require.ErrorIs(t, err, expectedErr)
	})

	t.Run("invalid role", func(t *testing.T) {
		validator := NewMessageValidator(netCfg, ns.Shares())

		slot := netCfg.Beacon.FirstSlotAtEpoch(1)
		height := specqbft.Height(slot)

		validSignedMessage := spectestingutils.TestingProposalMessageWithHeight(ks.Shares[1], 1, height)
		encodedValidSignedMessage, err := validSignedMessage.Encode()
		require.NoError(t, err)

		message := &spectypes.SSVMessage{
			MsgType: spectypes.SSVConsensusMsgType,
			MsgID:   spectypes.NewMsgID(netCfg.Domain, share.ValidatorPubKey, math.MaxUint64),
			Data:    encodedValidSignedMessage,
		}

		receivedAt := netCfg.Beacon.GetSlotStartTime(slot).Add(validator.waitAfterSlotStart(roleAttester))
		_, err = validator.ValidateMessage(message, receivedAt)
		require.ErrorIs(t, err, ErrInvalidRole)
	})

	t.Run("liquidated validator", func(t *testing.T) {
		// TODO
	})

	t.Run("not active validator", func(t *testing.T) {
		// TODO
	})

	t.Run("invalid QBFT message type", func(t *testing.T) {
		validator := NewMessageValidator(netCfg, ns.Shares())

		slot := netCfg.Beacon.FirstSlotAtEpoch(1)
		height := specqbft.Height(slot)

		msg := &specqbft.Message{
			MsgType:    math.MaxUint64,
			Height:     height,
			Round:      specqbft.FirstRound,
			Identifier: spectestingutils.TestingIdentifier,
			Root:       spectestingutils.TestingQBFTRootData,
		}
		signedMsg := spectestingutils.SignQBFTMsg(ks.Shares[1], 1, msg)

		encodedValidSignedMessage, err := signedMsg.Encode()
		require.NoError(t, err)

		message := &spectypes.SSVMessage{
			MsgType: spectypes.SSVConsensusMsgType,
			MsgID:   spectypes.NewMsgID(netCfg.Domain, share.ValidatorPubKey, roleAttester),
			Data:    encodedValidSignedMessage,
		}

		receivedAt := netCfg.Beacon.GetSlotStartTime(slot).Add(validator.waitAfterSlotStart(roleAttester))
		_, err = validator.ValidateMessage(message, receivedAt)
		require.NoError(t, err)
	})

	t.Run("wrong signature size", func(t *testing.T) {
		slot := netCfg.Beacon.FirstSlotAtEpoch(1)
		height := specqbft.Height(slot)

		validSignedMessage := spectestingutils.TestingProposalMessageWithHeight(ks.Shares[1], 1, height)
		validSignedMessage.Signature = []byte{0x1}

		_, err := validSignedMessage.Encode()
		require.Error(t, err)
	})

	t.Run("zero signature", func(t *testing.T) {
		validator := NewMessageValidator(netCfg, ns.Shares())

		slot := netCfg.Beacon.FirstSlotAtEpoch(1)
		height := specqbft.Height(slot)

		validSignedMessage := spectestingutils.TestingProposalMessageWithHeight(ks.Shares[1], 1, height)
		zeroSignature := [signatureSize]byte{}
		validSignedMessage.Signature = zeroSignature[:]

		encoded, err := validSignedMessage.Encode()
		require.NoError(t, err)

		message := &spectypes.SSVMessage{
			MsgType: spectypes.SSVConsensusMsgType,
			MsgID:   spectypes.NewMsgID(netCfg.Domain, share.ValidatorPubKey, roleAttester),
			Data:    encoded,
		}

		receivedAt := netCfg.Beacon.GetSlotStartTime(slot).Add(validator.waitAfterSlotStart(roleAttester))
		_, err = validator.ValidateMessage(message, receivedAt)
		require.ErrorIs(t, err, ErrZeroSignature)
	})

	t.Run("late message", func(t *testing.T) {
		validator := NewMessageValidator(netCfg, ns.Shares())

		slot := netCfg.Beacon.FirstSlotAtEpoch(1)
		height := specqbft.Height(slot)

		validSignedMessage := spectestingutils.TestingProposalMessageWithHeight(ks.Shares[1], 1, height)
		encodedValidSignedMessage, err := validSignedMessage.Encode()
		require.NoError(t, err)

		message := &spectypes.SSVMessage{
			MsgType: spectypes.SSVConsensusMsgType,
			MsgID:   spectypes.NewMsgID(netCfg.Domain, share.ValidatorPubKey, roleAttester),
			Data:    encodedValidSignedMessage,
		}

		receivedAt := netCfg.Beacon.GetSlotStartTime(slot).Add(validator.waitAfterSlotStart(roleAttester))
		_, err = validator.ValidateMessage(message, receivedAt.Add(50*netCfg.SlotDurationSec()))
		require.ErrorIs(t, err, ErrLateMessage)
	})

	t.Run("early message", func(t *testing.T) {
		validator := NewMessageValidator(netCfg, ns.Shares())

		slot := netCfg.Beacon.FirstSlotAtEpoch(1)
		height := specqbft.Height(slot)

		validSignedMessage := spectestingutils.TestingProposalMessageWithHeight(ks.Shares[1], 1, height)
		encodedValidSignedMessage, err := validSignedMessage.Encode()
		require.NoError(t, err)

		message := &spectypes.SSVMessage{
			MsgType: spectypes.SSVConsensusMsgType,
			MsgID:   spectypes.NewMsgID(netCfg.Domain, share.ValidatorPubKey, roleAttester),
			Data:    encodedValidSignedMessage,
		}

		receivedAt := netCfg.Beacon.GetSlotStartTime(slot - 1)
		_, err = validator.ValidateMessage(message, receivedAt)
		require.ErrorIs(t, err, ErrEarlyMessage)
	})

	t.Run("not leader", func(t *testing.T) {
		validator := NewMessageValidator(netCfg, ns.Shares())

		slot := netCfg.Beacon.FirstSlotAtEpoch(1)
		height := specqbft.Height(slot)

		validSignedMessage := spectestingutils.TestingProposalMessageWithHeight(ks.Shares[2], 2, height)
		encodedValidSignedMessage, err := validSignedMessage.Encode()
		require.NoError(t, err)

		message := &spectypes.SSVMessage{
			MsgType: spectypes.SSVConsensusMsgType,
			MsgID:   spectypes.NewMsgID(netCfg.Domain, share.ValidatorPubKey, roleAttester),
			Data:    encodedValidSignedMessage,
		}

		receivedAt := netCfg.Beacon.GetSlotStartTime(slot).Add(validator.waitAfterSlotStart(roleAttester))
		_, err = validator.ValidateMessage(message, receivedAt)
		expectedErr := ErrSignerNotLeader
		expectedErr.got = spectypes.OperatorID(2)
		expectedErr.want = spectypes.OperatorID(1)
		require.ErrorIs(t, err, expectedErr)
	})
}
