//go:build linux

package keys

import (
	"crypto/rand"
	"crypto/rsa"
	"github.com/stretchr/testify/require"
	"sync"
	"testing"
)

//type privateKeyWithRWMutex struct {
//	privKey       *rsa.PrivateKey
//	cachedPrivKey *openssl.PrivateKeyRSA
//	mu            sync.RWMutex
//}
//
//func (priv *privateKeyWithRWMutex) checkCachePrivkey() (*openssl.PrivateKeyRSA, error) {
//	priv.mu.RLock()
//	if priv.cachedPrivKey != nil {
//		defer priv.mu.RUnlock()
//		return priv.cachedPrivKey, nil
//	}
//	priv.mu.RUnlock()
//
//	opriv, err := rsaPrivateKeyToOpenSSL(priv.privKey)
//	if err != nil {
//		return nil, err
//	}
//	priv.mu.Lock()
//	defer priv.mu.Unlock()
//	priv.cachedPrivKey = opriv
//
//	return opriv, nil
//}

//
//func BenchmarkPrivKeyCacheWithSyncRWMutex(b *testing.B) {
//	key, err := rsa.GenerateKey(rand.Reader, 2048)
//	require.NoError(b, err)
//
//	pk := &privateKeyWithRWMutex{key, nil, sync.RWMutex{}}
//
//	b.RunParallel(func(pb *testing.PB) {
//		for pb.Next() {
//			wg := sync.WaitGroup{}
//			wg.Add(1000)
//			for i := 0; i < 1000; i++ {
//				go func() {
//					k, _ := pk.checkCachePrivkey()
//					require.NoError(b, err)
//					require.NotNil(b, k)
//					wg.Done()
//				}()
//			}
//			wg.Wait()
//		}
//	})
//}

func BenchmarkPrivKeyCacheSyncOnce(b *testing.B) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(b, err)
	msg := []byte("hello")
	priv := &privateKey{key, nil, sync.Once{}}
	pub := priv.Public().(*publicKey)

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			//wg := sync.WaitGroup{}
			//wg.Add(100)
			for i := 0; i < 100; i++ {
				//go func() {
				sig, err := priv.Sign(msg)
				require.NoError(b, err)
				require.NoError(b, VerifyRSA(pub, msg, sig))
				//wg.Done()
				//}()
			}
			//wg.Wait()
		}
	})
}

func BenchmarkPrivKeyNoCahce(b *testing.B) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(b, err)
	msg := []byte("hello")
	priv := &privateKeyStage{key, nil}
	pub := priv.Public().(*publicKeyStage)

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			for i := 0; i < 100; i++ {
				sig, err := priv.Sign(msg)
				require.NoError(b, err)
				require.NoError(b, VerifyRSAStage(pub, msg, sig))
			}
		}
	})
}
