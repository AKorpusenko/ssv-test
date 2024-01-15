package connections

import (
	"fmt"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// DummyConnectionIndex is a mock implementation of ConnectionIndex for testing
type DummyConnectionIndex struct {
	ConnectedPeers map[peer.ID]network.Connectedness
	MaxPeers       int
	BadPeers       map[peer.ID]bool
}

func NewDummyConnectionIndex(maxPeers int) *DummyConnectionIndex {
	return &DummyConnectionIndex{
		ConnectedPeers: make(map[peer.ID]network.Connectedness),
		MaxPeers:       maxPeers,
		BadPeers:       make(map[peer.ID]bool),
	}
}

func (dci *DummyConnectionIndex) Connectedness(id peer.ID) network.Connectedness {
	if conn, ok := dci.ConnectedPeers[id]; ok {
		return conn
	}
	return network.NotConnected
}

func (dci *DummyConnectionIndex) CanConnect(id peer.ID) bool {
	_, ok := dci.ConnectedPeers[id]
	return !ok
}

func (dci *DummyConnectionIndex) Limit(dir network.Direction) bool {
	return len(dci.ConnectedPeers) >= dci.MaxPeers
}

func (dci *DummyConnectionIndex) IsBad(logger *zap.Logger, id peer.ID) bool {
	if bad, ok := dci.BadPeers[id]; ok {
		return bad
	}
	return false
}

////////////////////////////////////////////////////////////////////////////

func setupTestEnvironment() (*ConnectionGater, peer.ID) {
	logger := zap.NewExample()
	testPeerID, _ := peer.Decode("12D3KooWEd...") // Example peer ID
	gater := NewConnectionGater(logger, 10, 1*time.Hour)

	return gater, testPeerID
}

func TestBlockPeer(t *testing.T) {
	gater, testPeerID := setupTestEnvironment()

	gater.BlockPeer(testPeerID)
	assert.True(t, gater.IsPeerBlocked(testPeerID), "Peer %v was not blocked as expected", testPeerID)
}

func TestIsPeerBlocked(t *testing.T) {
	gater, testPeerID := setupTestEnvironment()

	assert.False(t, gater.IsPeerBlocked(testPeerID), "Peer %v is unexpectedly blocked", testPeerID)
}

func TestBlacklistExpiration(t *testing.T) {
	gater, testPeerID := setupTestEnvironment()
	shortDuration := 500 * time.Millisecond
	gater.blackListDuration = shortDuration

	gater.BlockPeer(testPeerID)
	require.True(t, gater.IsPeerBlocked(testPeerID), "Peer %v was not initially blocked", testPeerID)

	time.Sleep(shortDuration + 50*time.Millisecond) // Wait for the blacklist duration plus a small buffer

	assert.False(t, gater.IsPeerBlocked(testPeerID), "Peer %v should not be blocked after expiration", testPeerID)
}

func TestInterceptPeerDial(t *testing.T) {
	gater, testPeerID := setupTestEnvironment()
	dummyIndex := NewDummyConnectionIndex(5) // Set maximum peers to 5
	gater.SetPeerIndex(dummyIndex)

	// Simulate that the number of connected peers is below the limit
	for i := 0; i < 4; i++ {
		dummyPeerID := peer.ID(fmt.Sprintf("Peer%d", i))
		dummyIndex.ConnectedPeers[dummyPeerID] = network.Connected
	}

	// Test peer dial when under the limit
	assert.True(t, gater.InterceptPeerDial(testPeerID), "InterceptPeerDial should allow dialing when under peer limit")

	// Add another peer to reach the limit
	dummyIndex.ConnectedPeers[peer.ID("Peer4")] = network.Connected

	// Test peer dial when at the limit
	assert.False(t, gater.InterceptPeerDial(testPeerID), "InterceptPeerDial should block dialing when at peer limit")
}

func TestInterceptSecured(t *testing.T) {
	gater, testPeerID := setupTestEnvironment()
	dummyIndex := NewDummyConnectionIndex(5)
	gater.SetPeerIndex(dummyIndex)

	// Simulate a good peer
	dummyIndex.BadPeers[testPeerID] = false

	// Test connection with a good peer
	assert.True(t, gater.InterceptSecured(network.DirOutbound, testPeerID, nil), "InterceptSecured should allow connection with a good peer")

	// Mark the peer as bad
	dummyIndex.BadPeers[testPeerID] = true

	// Test connection with a bad peer
	assert.False(t, gater.InterceptSecured(network.DirOutbound, testPeerID, nil), "InterceptSecured should block connection with a bad peer")
}