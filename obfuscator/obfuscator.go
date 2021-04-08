package obfuscator

import (
	"errors"

	"github.com/cyrildever/crumbl-exe/padder"
	"github.com/cyrildever/feistel"
	"github.com/cyrildever/feistel/common/utils/base256"
	"github.com/cyrildever/feistel/common/utils/hash"
)

const (
	// DEFAULT_HASH_ENGINE ...
	DEFAULT_HASH_ENGINE = hash.SHA_256

	// DEFAULT_KEY_STRING ...
	DEFAULT_KEY_STRING = "8ed9dcc1701c064f0fd7ae235f15143f989920e0ee9658bb7882c8d7d5f05692" // SHA-256("crumbl by Edgewhere")

	// DEFAULT_ROUNDS ...
	DEFAULT_ROUNDS = 10
)

//--- TYPES

// Obfuscator ...
type Obfuscator struct {
	cipher *feistel.FPECipher
}

//--- METHODS

// Apply transforms the passed string to an obfuscated byte array through a Feistel cipher
func (o Obfuscator) Apply(data string) (obfuscated []byte, err error) {
	if len(data)%2 == 1 {
		padded, _, e := padder.Apply([]byte(data), len(data)+1, true)
		if err != nil {
			err = e
			return
		}
		data = string(padded)
	}
	// Apply the Feistel cipher
	ob, err := o.cipher.Encrypt(data)
	if err != nil {
		return
	}
	obfuscated = ob.Bytes()
	return
}

// Unapply transforms the passed obfuscated byte array to a deobfuscated string through a Feistel cipher
func (o Obfuscator) Unapply(obfuscated []byte) (deobfuscated string, err error) {
	if len(string(obfuscated))%2 != 0 {
		err = errors.New("invalid obfuscated data")
		return
	}

	// Unapply the Feistel cipher
	readable := base256.ToBase256Readable(obfuscated)
	d, err := o.cipher.Decrypt(readable)
	if err != nil {
		return
	}
	unpadded, _, err := padder.Unapply([]byte(d))
	if err != nil {
		return
	}
	deobfuscated = string(unpadded)
	return
}

//--- FUNCTIONS

// NewObfuscator ...
func NewObfuscator(cipher *feistel.FPECipher) *Obfuscator {
	return &Obfuscator{
		cipher: cipher,
	}
}
