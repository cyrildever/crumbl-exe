package decrypter

import (
	"errors"

	"github.com/edgewhere/crumbl-exe/crypto"
	"github.com/edgewhere/crumbl-exe/crypto/ecies"
	"github.com/edgewhere/crumbl-exe/crypto/rsa"
	"github.com/edgewhere/crumbl-exe/encrypter"
	"github.com/edgewhere/crumbl-exe/models/core"
	"github.com/edgewhere/crumbl-exe/models/signer"
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
