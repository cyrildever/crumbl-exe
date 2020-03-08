package decrypter

import (
	"fmt"

	"github.com/edgewhere/crumbl-exe/crypto"
	"github.com/edgewhere/crumbl-exe/utils"
)

//--- TYPES

// Collector ...
type Collector struct {
	Map              map[int]Uncrumb
	NumberOfSlices   int
	VerificationHash string
	HashEngine       string
}

//--- METHODS

// Check verifies the passed data against the verification hash
func (c *Collector) Check(data []byte) bool {
	hashedData, err := crypto.Hash(data, c.HashEngine)
	if err != nil {
		return false
	}
	return utils.ToHex(hashedData) == c.VerificationHash
}

// ToObfuscated returns the concatenated slices into the obfuscated string
func (c *Collector) ToObfuscated() (obfuscated []byte, err error) {
	var o string
	for i := 0; i < c.NumberOfSlices; i++ {
		uncrumb, found := c.Map[i]
		if !found {
			err = fmt.Errorf("missing slice with index: %d", i)
			return
		}
		o += utils.Unpad(string(uncrumb.ToSlice()))
	}
	obfuscated = []byte(o)
	return
}
