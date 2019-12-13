package encrypter_test

import (
	"crumbl/encrypter"
	"crumbl/models/core"
	"testing"

	"gotest.tools/assert"
)

// TestParse ...
func TestParse(t *testing.T) {
	crumbStr := "01000cRWRnZXdoZXJl"
	idx, ln, enc, err := encrypter.Parse(crumbStr)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, idx, 1)
	assert.Equal(t, ln, 12)
	assert.Equal(t, enc, "RWRnZXdoZXJl")
	assert.Equal(t, "Edgewhere", string(core.Base64("RWRnZXdoZXJl").Decoded()))
}

// TestToCrumb ...
func TestToCrumb(t *testing.T) {
	ref := encrypter.Crumb{
		Encrypted: core.Base64("RWRnZXdoZXJl"),
		Index:     1,
		Length:    12,
	}
	str := "01000cRWRnZXdoZXJl"
	crumb, err := encrypter.ToCrumb(str)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, ref, crumb)
}
