package hasher_test

import (
	"strings"
	"testing"

	"github.com/edgewhere/crumbl-exe/crypto"
	"github.com/edgewhere/crumbl-exe/encrypter"
	"github.com/edgewhere/crumbl-exe/hasher"
	"github.com/edgewhere/crumbl-exe/utils"
	"gotest.tools/assert"
)

var crumbs = []encrypter.Crumb{
	encrypter.Crumb{
		Index:     0,
		Length:    12,
		Encrypted: "RWRnZXdoZXJl",
	},
}

// TestApply ...
func TestApply(t *testing.T) {
	expected := "c5066fffa7ee8e9a2013c62b465c993d51f9ec5191435c3e078d8801859c74d6"
	source := "data to hash"
	hashered, err := hasher.Apply(source, crumbs)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, hashered, expected)
	assert.Equal(t, len(hashered), crypto.DEFAULT_HASH_LENGTH)

	hSrc, _ := crypto.Hash([]byte(source), crypto.DEFAULT_HASH_ENGINE)
	firstChars := utils.ToHex(hSrc)[:32]
	assert.Assert(t, strings.HasPrefix(hashered, firstChars))

	_, err = hasher.Apply(source, []encrypter.Crumb{
		encrypter.Crumb{
			Index:     1, // Wrong index
			Length:    12,
			Encrypted: "RWRnZXdoZXJl",
		},
	})
	assert.Error(t, err, "owner's crumbs not present")
}

// TestUnapply ...
func TestUnapply(t *testing.T) {
	ref := "c5066fffa7ee8e9a2013c62b465c993d149d8b34e62b394c62c8ec66e0eb1cb3"
	hashered := "c5066fffa7ee8e9a2013c62b465c993d51f9ec5191435c3e078d8801859c74d6"
	found, err := hasher.Unapply(hashered, crumbs)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, found, ref)
}
