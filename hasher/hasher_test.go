package hasher_test

import (
	"strings"
	"testing"

	"github.com/cyrildever/crumbl-exe/crypto"
	"github.com/cyrildever/crumbl-exe/encrypter"
	"github.com/cyrildever/crumbl-exe/hasher"
	"github.com/cyrildever/crumbl-exe/models/core"
	"github.com/cyrildever/crumbl-exe/utils"
	"gotest.tools/assert"
)

var crumbs = []encrypter.Crumb{
	{
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
		{
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

	// Like in TypeScript
	crumbs2 := []encrypter.Crumb{
		{
			Index:     0,
			Encrypted: core.Base64("BHbIv7jmXdjb3n7+/Ewg1Br4EXYksmb4RmavTQsDVJAFY/he1rs7gpRY9+waPCww3YMzr5IIWFYN8LDVDDxV2bdTGBNjHWbsb4WRM2ItLFVYubxBto/6pfGyXJ0ZriYjL2RCVtPw8cdJrkeXqSqOEz1ICBTN9UOBZw=="),
			Length:    164,
		},
		{
			Index:     0,
			Encrypted: core.Base64("BLaggeNjl7tsFhAymEipkuIco8xG8trm6E+4WzrTX7spC0DmdyTFhU8enJV2WERxOaF7iy6E64/2+2wIL/MqRMnyRnJJJDab6d7pTWMSEVOUAvEFugTP95XpnnZcDyzLdZ2J+YBbMYtRcnxH4TJA9AIwksl0oJRA/w=="),
			Length:    164,
		},
	}
	ref = "cc8b00be1cc7592806ba4f8fe4411d3744121dc12e6201dc36e873f7fd9a6bae"
	hashered = "cc8b00be1cc7592806ba4f8fe4411d374064d57e96845c04ed360d0901d64b7a"
	found, err = hasher.Unapply(hashered, crumbs2)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, found, ref)
}
