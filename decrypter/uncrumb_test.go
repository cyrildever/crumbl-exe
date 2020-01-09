package decrypter_test

import (
	"crumbl/decrypter"
	"crumbl/models/core"
	"testing"

	"gotest.tools/assert"
)

// TestParse ...
func TestParse(t *testing.T) {
	uncrumbStr := "%01RWRnZXdoZXJl"
	idx, dec, err := decrypter.Parse(uncrumbStr)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, idx, 1)
	assert.Equal(t, dec, "RWRnZXdoZXJl")
	assert.Equal(t, "Edgewhere", string(core.Base64("RWRnZXdoZXJl").Decoded()))
}

// TestToUncrumb ...
func TestToUncrumb(t *testing.T) {
	ref := decrypter.Uncrumb{
		Deciphered: core.Base64("RWRnZXdoZXJl"),
		Index:      1,
	}
	str := "01RWRnZXdoZXJl" // PARTIAL_PREFIX is ignored anyway
	uncrumb, err := decrypter.ToUncrumb(str)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, ref, uncrumb)
}

// TestToSlice ...
func TestToSlice(t *testing.T) {
	ref := "Edgewhere"
	uncrumb := decrypter.Uncrumb{
		Deciphered: core.Base64("RWRnZXdoZXJl"),
		Index:      1,
	}
	slice := uncrumb.ToSlice()
	assert.Equal(t, ref, string(slice))
}
