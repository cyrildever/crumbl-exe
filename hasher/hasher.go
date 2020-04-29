package hasher

import (
	"errors"
	"sort"
	"strings"

	"github.com/edgewhere/crumbl-exe/crypto"
	"github.com/edgewhere/crumbl-exe/encrypter"
	"github.com/edgewhere/crumbl-exe/models/core"
	"github.com/edgewhere/crumbl-exe/utils"
	"github.com/edgewhere/crumbl-exe/utils/xor"
)

// The Hasher generates a modified hash unique to a source to prepend the crumbs in the finalized Crumbl.
// It takes the datasource, hash it with the default hash engine, then uses the lexicographically sorted owner(s) crumb(s) encrypted part
// to XOR them with the final 32 characters of the hash. The final modified hash could therefore be represented by the following formula:
//  N - 32 last chars of the hex string of the hashed source + (32 last chars ^ padded/cut lexicographically sorted owners encrypted crumbs).toHex

const (
	// NUMBER_OF_CHARACTERS ...
	NUMBER_OF_CHARACTERS = 32
)

// Apply ...
func Apply(source string, crumbs []encrypter.Crumb) (string, error) {
	hSrc, err := crypto.Hash([]byte(source), crypto.DEFAULT_HASH_ENGINE)
	if err != nil {
		return "", err
	}
	stringifiedHash := utils.ToHex(hSrc)
	length := len(stringifiedHash)
	if length < NUMBER_OF_CHARACTERS {
		return "", errors.New("wrong hash algorithm")
	}
	lastChars := stringifiedHash[length-NUMBER_OF_CHARACTERS:]
	var sortedOwnerCrumbs []string
	for _, crumb := range crumbs {
		if crumb.Index == 0 {
			sortedOwnerCrumbs = append(sortedOwnerCrumbs, crumb.Encrypted.String())
		}
	}
	if len(sortedOwnerCrumbs) == 0 {
		return "", errors.New("owner's crumbs not present") // TODO Typed error
	}
	sort.Strings(sortedOwnerCrumbs)
	concat := core.Base64(strings.Join(sortedOwnerCrumbs, "")).Bytes()
	mask := buildMask(concat, NUMBER_OF_CHARACTERS/2)
	lastBytes, _ := utils.FromHex(lastChars)
	xored, err := xor.Bytes(lastBytes, mask)
	if err != nil {
		return "", err
	}
	xoredHex := utils.ToHex([]byte(xored))
	return stringifiedHash[:length-NUMBER_OF_CHARACTERS] + xoredHex, nil
}

// Unapply ...
func Unapply(hashered string, crumbs []encrypter.Crumb) (string, error) {
	if len(hashered) < NUMBER_OF_CHARACTERS {
		return "", errors.New("wrong hashered value")
	}
	xoredHex := hashered[len(hashered)-NUMBER_OF_CHARACTERS:]
	xored, err := utils.FromHex(xoredHex)
	if err != nil {
		return "", err
	}
	var sortedOwnerCrumbs []string
	for _, crumb := range crumbs {
		if crumb.Index == 0 {
			sortedOwnerCrumbs = append(sortedOwnerCrumbs, crumb.Encrypted.String())
		}
	}
	if len(sortedOwnerCrumbs) == 0 {
		return "", errors.New("owner's crumbs not present") // TODO Typed error
	}
	sort.Strings(sortedOwnerCrumbs)
	concat := core.Base64(strings.Join(sortedOwnerCrumbs, "")).Bytes()
	mask := buildMask(concat, NUMBER_OF_CHARACTERS/2)
	lastBytes, err := xor.Bytes(xored, mask)
	if err != nil {
		return "", err
	}
	lastChars := utils.ToHex(lastBytes)
	return hashered[:len(hashered)-NUMBER_OF_CHARACTERS] + lastChars, nil
}

// buildMask creates a data mask repeating or cutting the past key to make it the wished length.
func buildMask(key []byte, length int) (mask []byte) {
	if len(key) == 0 {
		mask = make([]byte, length)
		return
	}
	if len(key) >= length {
		return key[:length]
	}
	quotient, remainder, _ := utils.EuclideanDivision(length, len(key))
	for i := 0; i < quotient; i++ {
		mask = append(mask, key...)
	}
	return append(mask, key[:remainder]...)
}
