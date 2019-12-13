package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// Encrypt ...
func Encrypt(msg, publicKeyBytes []byte) ([]byte, error) {
	pk, err := BytesToPublicKey(publicKeyBytes)
	if err != nil {
		return nil, err
	}
	return EncryptWithPublicKey(msg, pk)
}

// Decrypt ...
func Decrypt(ciphered, privateKeyBytes []byte) ([]byte, error) {
	sk, err := BytesToPrivateKey(privateKeyBytes)
	if err != nil {
		return nil, err
	}
	return DecryptWithPrivateKey(ciphered, sk)
}

//--- utilities

// GenerateKeyPair generates a new key pair
func GenerateKeyPair(bits int) (sk *rsa.PrivateKey, pk *rsa.PublicKey, err error) {
	privkey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return
	}
	sk = privkey
	pk = &privkey.PublicKey
	return
}

// PrivateKeyToBytes transforms private key to bytes
func PrivateKeyToBytes(priv *rsa.PrivateKey) []byte {
	privBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priv),
		},
	)
	return privBytes
}

// PublicKeyToBytes transforms public key to bytes
func PublicKeyToBytes(pub *rsa.PublicKey) ([]byte, error) {
	pubASN1, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})
	return pubBytes, nil
}

// BytesToPrivateKey converts bytes to private key
func BytesToPrivateKey(priv []byte) (sk *rsa.PrivateKey, err error) {
	block, _ := pem.Decode(priv)
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	if enc {
		b, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			return
		}
	}
	key, err := x509.ParsePKCS1PrivateKey(b)
	if err != nil {
		return
	}
	return key, nil
}

// BytesToPublicKey converts bytes to public key
func BytesToPublicKey(pub []byte) (pk *rsa.PublicKey, err error) {
	block, _ := pem.Decode(pub)
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	if enc {
		b, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			return
		}
	}
	ifc, err := x509.ParsePKIXPublicKey(b)
	if err != nil {
		return
	}
	key, ok := ifc.(*rsa.PublicKey)
	if !ok {
		err = fmt.Errorf("not ok")
		return
	}
	return key, nil
}

// EncryptWithPublicKey encrypts data with public key
func EncryptWithPublicKey(msg []byte, pub *rsa.PublicKey) ([]byte, error) {
	hash := sha512.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, pub, msg, nil)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

// DecryptWithPrivateKey decrypts data with private key
func DecryptWithPrivateKey(ciphertext []byte, priv *rsa.PrivateKey) ([]byte, error) {
	hash := sha512.New()
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, priv, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
