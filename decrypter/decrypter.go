package decrypter

import (
	"crumbl/crypto"
	"crumbl/crypto/ecies"
	"crumbl/crypto/rsa"
	"crumbl/encrypter"
	"crumbl/models/core"
	"crumbl/models/signer"
	"errors"
)

// Decrypt decrypts the passed encrypted Crumb and returns it as an Uncrumb
func Decrypt(encrypted encrypter.Crumb, s signer.Signer) (data Uncrumb, err error) {
	var dec []byte
	switch s.EncryptionAlgorithm {
	case crypto.ECIES_ALGORITHM:
		deciphered, e := ecies.Decrypt(encrypted.Encrypted.Bytes(), s.PrivateKey, s.PublicKey)
		if e != nil {
			err = e
			return
		}
		dec = deciphered
	case crypto.RSA_ALGORITHM:
		deciphered, e := rsa.Decrypt(encrypted.Encrypted.Bytes(), s.PrivateKey)
		if e != nil {
			err = e
			return
		}
		dec = deciphered
	default:
		err = errors.New("unknown encryption algorithm: " + s.EncryptionAlgorithm)
		return
	}
	data = Uncrumb{
		Deciphered: core.ToBase64(dec),
		Index:      encrypted.Index,
	}
	return
}
