package ecies

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"math/big"

	ethecies "github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

// Encrypt ...
func Encrypt(msg, publicKeyBytes []byte) ([]byte, error) {
	pk, err := PublicKeyFrom(publicKeyBytes)
	if err != nil {
		return nil, err
	}
	return ethecies.Encrypt(rand.Reader, &pk, msg, nil, nil)
}

// Decrypt ...
func Decrypt(ciphered, privateKeyBytes, publicKeyBytes []byte) ([]byte, error) {
	sk, err := PrivateKeyFrom(privateKeyBytes, publicKeyBytes)
	if err != nil {
		return nil, err
	}
	return sk.Decrypt(ciphered, nil, nil)
}

// PublicKeyFrom ...
func PublicKeyFrom(publicKeyBytes []byte) (pk ethecies.PublicKey, err error) {
	x, y := elliptic.Unmarshal(secp256k1.S256(), publicKeyBytes)
	if x == nil || y == nil {
		err = errors.New("invalid public key")
		return
	}
	pubkey := ecdsa.PublicKey{
		Curve: secp256k1.S256(),
		X:     x,
		Y:     y,
	}
	pk = (*ethecies.ImportECDSAPublic(&pubkey))
	return
}

// PrivateKeyFrom ...
func PrivateKeyFrom(privateKeyBytes, publicKeyBytes []byte) (sk ethecies.PrivateKey, err error) {
	pk, err := PublicKeyFrom(publicKeyBytes)
	if err != nil {
		return
	}
	d := new(big.Int)
	d.SetBytes(privateKeyBytes)
	sk = ethecies.PrivateKey{
		PublicKey: pk,
		D:         d,
	}
	return
}
