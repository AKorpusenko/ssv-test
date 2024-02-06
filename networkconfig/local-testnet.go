package networkconfig

import (
	spectypes "github.com/bloxapp/ssv-spec/types"

	"github.com/bloxapp/ssv/protocol/v2/blockchain/beacon"
)

type beaconTestnet struct {
	spectypes.BeaconNetwork
}

func (n beaconTestnet) MinGenesisTime() uint64 {
	return 1689072978
}

var LocalTestnet = NetworkConfig{
	Name:                 "local-testnet",
	Beacon:               beacon.NewNetwork(beaconTestnet{spectypes.PraterNetwork}),
	Domain:               spectypes.JatoV2Testnet,
	GenesisEpoch:         1,
	RegistryContractAddr: "0xC3CD9A0aE89Fff83b71b58b6512D43F8a41f363D",
	Bootnodes: []string{
		"enr:-Li4QLR4Y1VbwiqFYKy6m-WFHRNDjhMDZ_qJwIABu2PY9BHjIYwCKpTvvkVmZhu43Q6zVA29sEUhtz10rQjDJkK3Hd-GAYiGrW2Bh2F0dG5ldHOIAAAAAAAAAACEZXRoMpD1pf1CAAAAAP__________gmlkgnY0gmlwhCLdu_SJc2VjcDI1NmsxoQJTcI7GHPw-ZqIflPZYYDK_guurp_gsAFF5Erns3-PAvIN0Y3CCE4mDdWRwgg-h",
	},
}
