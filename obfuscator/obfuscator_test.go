package obfuscator_test

import (
	"testing"

	"github.com/cyrildever/crumbl-exe/obfuscator"
	"github.com/cyrildever/crumbl-exe/utils"
	"github.com/cyrildever/feistel"
	"gotest.tools/assert"
)

var cipher = feistel.NewFPECipher(obfuscator.DEFAULT_HASH_ENGINE, obfuscator.DEFAULT_KEY_STRING, obfuscator.DEFAULT_ROUNDS)

// TestObfuscatorApply ...
func TestObfuscatorApply(t *testing.T) {
	obfuscated, err := obfuscator.NewObfuscator(cipher).Apply("Edgewhere")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, utils.ToHex(obfuscated), "3d7c0a0f51415a521054")
}

// TestObfuscatorUnapply ...
func TestObfuscatorUnapply(t *testing.T) {
	ref := "Edgewhere"
	obfuscated, _ := utils.FromHex("3d7c0a0f51415a521054")
	deobfuscated, err := obfuscator.NewObfuscator(cipher).Unapply(obfuscated)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, deobfuscated, ref)
}
