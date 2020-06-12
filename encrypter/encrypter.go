package encrypter

import (
	"errors"

	"github.com/cyrildever/crumbl-exe/crypto"
	"github.com/cyrildever/crumbl-exe/crypto/ecies"
	"github.com/cyrildever/crumbl-exe/crypto/rsa"
	"github.com/cyrildever/crumbl-exe/models/core"
	"github.com/cyrildever/crumbl-exe/models/signer"
	"github.com/cyrildever/crumbl-exe/slicer"
)

// Encrypt returns the base64-encoded encrypted slice as Crumb:
// It takes the slice data and index as well as the signer as arguments,
// and returns the corresponding Crumb object, or an error if any.
func Encrypt(data slicer.Slice, index int, s signer.Signer) (c Crumb, err error) {
	var enc []byte
	switch s.EncryptionAlgorithm {
	case crypto.ECIES_ALGORITHM:
		crypted, e := ecies.Encrypt([]byte(data), s.PublicKey)
		if e != nil {
			err = e
			return
		}
		enc = crypted
	case crypto.RSA_ALGORITHM:
		crypted, e := rsa.Encrypt([]byte(data), s.PublicKey)
		if e != nil {
			err = e
			return
		}
		enc = crypted
	default:
		err = errors.New("unknown encryption algorithm: " + s.EncryptionAlgorithm)
		return
	}
	b64 := core.ToBase64(enc)
	c = Crumb{
		Encrypted: b64,
		Index:     index,
		Length:    len(b64.String()),
	}
	return
}
