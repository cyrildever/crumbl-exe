package crypto_test

import (
	"testing"

	"github.com/edgewhere/crumbl-exe/crypto"
	"github.com/edgewhere/crumbl-exe/utils"

	"gotest.tools/assert"
)

// TestHash ...
func TestHash(t *testing.T) {
	ref := "c0c77f225dd222144bc4ef79dca00ab7d955f26da2b1e0f25df81f8a7e86917c"
	hash, err := crypto.Hash([]byte("Edgewhere"), crypto.DEFAULT_HASH_ENGINE)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, ref, utils.ToHex(hash))

	_, err = crypto.Hash([]byte("Edgewhere"), "wrong-hash-engine")
	assert.Assert(t, err != nil && err.Error() == "invalid hash engine")
}
