package duties

import (
	"context"
	"math/big"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	spectypes "github.com/bloxapp/ssv-spec/types"
	"go.uber.org/zap"

	"github.com/bloxapp/ssv/logging/fields"
)

const voluntaryExitSlotsToPostpone = phase0.Slot(4)

type ExitDescriptor struct {
	PubKey         phase0.BLSPubKey
	ValidatorIndex phase0.ValidatorIndex
	BlockNumber    uint64
}

type VoluntaryExitHandler struct {
	baseHandler
	validatorExitCh <-chan ExitDescriptor
	dutyQueue       []*spectypes.Duty
}

func NewVoluntaryExitHandler(validatorExitCh <-chan ExitDescriptor) *VoluntaryExitHandler {
	return &VoluntaryExitHandler{
		validatorExitCh: validatorExitCh,
		dutyQueue:       make([]*spectypes.Duty, 0),
	}
}

func (h *VoluntaryExitHandler) Name() string {
	return spectypes.BNRoleVoluntaryExit.String()
}

func (h *VoluntaryExitHandler) HandleDuties(ctx context.Context) {
	h.logger.Info("starting duty handler")
	defer h.logger.Info("stopping duty handler")

	for {
		select {
		case <-ctx.Done():
			h.logger.Debug("🛠 context done")
			return

		case <-h.ticker.Next():
			h.logger.Debug("🛠 before ticker event")

			currentSlot := h.ticker.Slot()

			h.logger.Debug("🛠 ticker event", fields.Slot(currentSlot))

			var dutiesForExecution, pendingDuties []*spectypes.Duty

			for _, duty := range h.dutyQueue {
				if duty.Slot <= currentSlot {
					dutiesForExecution = append(dutiesForExecution, duty)
				} else {
					pendingDuties = append(pendingDuties, duty)
				}
			}

			h.dutyQueue = pendingDuties

			if dutyCount := len(dutiesForExecution); dutyCount != 0 {
				h.executeDuties(h.logger, dutiesForExecution)
				h.logger.Debug("executed voluntary exit duties",
					fields.Slot(currentSlot),
					fields.Count(dutyCount))
			}

		case exitDescriptor := <-h.validatorExitCh:
			h.logger.Debug("🛠 scheduling duty for execution",
				fields.PubKey(exitDescriptor.PubKey[:]),
				fields.BlockNumber(exitDescriptor.BlockNumber),
			)

			block, err := h.executionClient.BlockByNumber(ctx, new(big.Int).SetUint64(exitDescriptor.BlockNumber))
			if err != nil {
				h.logger.Warn("failed to get block time from execution client, skipping voluntary exit duty",
					zap.Error(err))
				continue
			}

			blockSlot := h.network.Beacon.EstimatedSlotAtTime(int64(block.Time()))

			dutySlot := blockSlot + voluntaryExitSlotsToPostpone

			duty := &spectypes.Duty{
				Type:           spectypes.BNRoleVoluntaryExit,
				PubKey:         exitDescriptor.PubKey,
				Slot:           dutySlot,
				ValidatorIndex: exitDescriptor.ValidatorIndex,
			}

			h.dutyQueue = append(h.dutyQueue, duty)

			h.logger.Debug("🛠 scheduled duty for execution",
				zap.Uint64("block_slot", uint64(blockSlot)),
				zap.Uint64("duty_slot", uint64(dutySlot)),
				fields.BlockNumber(exitDescriptor.BlockNumber),
				fields.PubKey(exitDescriptor.PubKey[:]),
			)
		}
	}
}
