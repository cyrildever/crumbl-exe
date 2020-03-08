package utils_test

import (
	"testing"

	"github.com/edgewhere/crumbl-exe/utils"

	"gotest.tools/assert"
)

// TestIntToHex ...
func TestIntToHex(t *testing.T) {
	ref1 := "ff"
	i1 := 255
	hex1 := utils.IntToHex(i1)
	assert.Equal(t, ref1, hex1)

	ref2 := "0"
	i2 := 0
	hex2 := utils.IntToHex(i2)
	assert.Equal(t, ref2, hex2)
}

// TestHexToInt ...
func TestHexToInt(t *testing.T) {
	ref := 255
	hex := "00ff"
	i, err := utils.HexToInt(hex)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, ref, i)
}

// TestToHex ...
func TestToHex(t *testing.T) {
	ref := "456467657768657265"
	bytes := []byte("Edgewhere")
	hex := utils.ToHex(bytes)
	assert.Equal(t, ref, hex)
}
