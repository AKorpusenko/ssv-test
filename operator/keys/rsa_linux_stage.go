//go:build linux

package keys

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"github.com/bloxapp/ssv/utils/rsaencryption"
	"math/big"

	"github.com/microsoft/go-crypto-openssl/openssl"
	"github.com/microsoft/go-crypto-openssl/openssl/bbig/bridge"
)

type privateKeyStage struct {
	privKey       *rsa.PrivateKey
	cachedPrivKey *openssl.PrivateKeyRSA
}

type publicKeyStage struct {
	pubKey       *rsa.PublicKey
	cachedPubkey *openssl.PublicKeyRSA
}

//
//func rsaPrivateKeyToOpenSSLStage(priv *rsa.PrivateKey) (*openssl.PrivateKeyRSA, error) {
//	return bridge.NewPrivateKeyRSA(
//		priv.N,
//		big.NewInt(int64(priv.E)),
//		priv.D,
//		priv.Primes[0],
//		priv.Primes[1],
//		priv.Precomputed.Dp,
//		priv.Precomputed.Dq,
//		priv.Precomputed.Qinv,
//	)
//}

func rsaPublicKeyToOpenSSLStage(pub *rsa.PublicKey) (*openssl.PublicKeyRSA, error) {
	return bridge.NewPublicKeyRSA(
		pub.N,
		big.NewInt(int64(pub.E)),
	)
}

func checkCachePrivkeyStage(priv *privateKeyStage) (*openssl.PrivateKeyRSA, error) {
	if priv.cachedPrivKey != nil {
		return priv.cachedPrivKey, nil
	}
	opriv, err := rsaPrivateKeyToOpenSSL(priv.privKey)
	if err != nil {
		return nil, err
	}
	priv.cachedPrivKey = opriv

	return opriv, nil
}

func SignRSAStage(priv *privateKeyStage, data []byte) ([]byte, error) {
	opriv, err := checkCachePrivkeyStage(priv)
	if err != nil {
		return nil, err
	}
	return openssl.SignRSAPKCS1v15(opriv, crypto.SHA256, data)
}

func checkCachePubkeyStage(pub *publicKeyStage) (*openssl.PublicKeyRSA, error) {
	if pub.cachedPubkey != nil {
		return pub.cachedPubkey, nil
	}

	opub, err := rsaPublicKeyToOpenSSLStage(pub.pubKey)
	if err != nil {
		return nil, err
	}
	pub.cachedPubkey = opub

	return opub, nil
}

func EncryptRSAStage(pub *publicKeyStage, data []byte) ([]byte, error) {
	opub, err := checkCachePubkeyStage(pub)
	if err != nil {
		return nil, err
	}
	return openssl.EncryptRSAPKCS1(opub, data)
}

func VerifyRSAStage(pub *publicKeyStage, data, signature []byte) error {
	opub, err := checkCachePubkeyStage(pub)
	if err != nil {
		return err
	}
	hashed := sha256.Sum256(data)
	return openssl.VerifyRSAPKCS1v15(opub, crypto.SHA256, hashed[:], signature)
}

func (p *privateKeyStage) Public() OperatorPublicKey {
	pubKey := p.privKey.PublicKey
	return &publicKeyStage{pubKey: &pubKey}
}

func (p *privateKeyStage) Sign(data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)
	return SignRSAStage(p, hash[:])
}

func (p *privateKeyStage) Decrypt(data []byte) ([]byte, error) {
	return rsaencryption.DecodeKey(p.privKey, data)
}

func (p *privateKeyStage) Bytes() []byte {
	return rsaencryption.PrivateKeyToByte(p.privKey)
}

func (p *privateKeyStage) Base64() []byte {
	return []byte(rsaencryption.ExtractPrivateKey(p.privKey))
}

func (p *privateKeyStage) StorageHash() (string, error) {
	return rsaencryption.HashRsaKey(rsaencryption.PrivateKeyToByte(p.privKey))
}

func (p *privateKeyStage) EKMHash() (string, error) {
	return rsaencryption.HashRsaKey(x509.MarshalPKCS1PrivateKey(p.privKey))
}

//
//func PublicKeyFromStringStage(pubKeyString string) (OperatorPublicKey, error) {
//	pubPem, err := base64.StdEncoding.DecodeString(pubKeyString)
//	if err != nil {
//		return nil, err
//	}
//
//	pubKey, err := rsaencryption.ConvertPemToPublicKey(pubPem)
//	if err != nil {
//		return nil, err
//	}
//
//	return &publicKeyStage{
//		pubKey: pubKey,
//	}, nil
//}

func (p *publicKeyStage) Encrypt(data []byte) ([]byte, error) {
	return EncryptRSAStage(p, data)
}

func (p *publicKeyStage) Verify(data []byte, signature []byte) error {
	return VerifyRSAStage(p, data, signature)
}

func (p *publicKeyStage) Base64() ([]byte, error) {
	b, err := rsaencryption.ExtractPublicKey(p.pubKey)
	if err != nil {
		return nil, err
	}
	return []byte(b), err
}
