package crypto

import (
	"crumbl/utils"
	"crypto/sha256"
	"errors"
	"strings"
)

const (
	// DEFAULT_HASH_ENGINE ...
	DEFAULT_HASH_ENGINE = "sha-256"

	// DEFAULT_HASH_LENGTH ...
	DEFAULT_HASH_LENGTH = 64
)

var authorizedAlgorithms = "ecies:rsa" // TODO Add any new authorized algorithm name after a colon

// ExistsAlgorithm ...
func ExistsAlgorithm(name string) bool {
	return strings.Contains(authorizedAlgorithms, name)
}

// GetKeyBytes returns the appropriate byte array for the passed key and algorithm name
func GetKeyBytes(key string, algo string) (bytes []byte, err error) {
	switch algo {
	case "ecies":
		return utils.FromHex(key)
	case "rsa":
		return []byte(key), nil
	default:
		return []byte(key), nil
	}
}

// Hash hashes the passed byte array using SHA-256 hash algorithm (as of the latest version of the Crumbl&trade;)
func Hash(input []byte, engine string) (h []byte, err error) {
	if engine == DEFAULT_HASH_ENGINE {
		hasher := sha256.New()
		_, e := hasher.Write(input)
		if err != nil {
			err = e
			return
		}
		h = hasher.Sum(nil)
	} else {
		err = errors.New("invalid hash engine")
		return
	}
	return
}
