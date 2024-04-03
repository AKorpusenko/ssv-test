//go:build linux

package keys

import (
	"crypto/rand"
	"crypto/rsa"
	"github.com/microsoft/go-crypto-openssl/openssl"
	"github.com/stretchr/testify/require"
	"sync"
	"testing"
)

type privateKeyWithRWMutex struct {
	privKey       *rsa.PrivateKey
	cachedPrivKey *openssl.PrivateKeyRSA
	mu            sync.RWMutex
}

func (priv *privateKeyWithRWMutex) checkCachePrivkey() (*openssl.PrivateKeyRSA, error) {
	priv.mu.RLock()
	if priv.cachedPrivKey != nil {
		defer priv.mu.RUnlock()
		return priv.cachedPrivKey, nil
	}
	priv.mu.RUnlock()

	opriv, err := rsaPrivateKeyToOpenSSL(priv.privKey)
	if err != nil {
		return nil, err
	}
	priv.mu.Lock()
	defer priv.mu.Unlock()
	priv.cachedPrivKey = opriv

	return opriv, nil
}

func BenchmarkPrivKeyCacheWithSyncRWMutex(b *testing.B) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(b, err)

	pk := &privateKeyWithRWMutex{key, nil, sync.RWMutex{}}

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			key, err := pk.checkCachePrivkey()
			require.NoError(b, err)
			require.NotNil(b, key)
		}
	})
}

func BenchmarkPrivKeyCacheSyncOnce(b *testing.B) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(b, err)

	pk := &privateKey{key, nil, sync.Once{}}

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			key, err := checkCachePrivkey(pk)
			require.NoError(b, err)
			require.NotNil(b, key)
		}
	})
}
