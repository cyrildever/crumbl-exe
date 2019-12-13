package utils_test

import (
	"crumbl/utils"
	"testing"

	"gotest.tools/assert"
)

// TestLeftPads ...
func TestLeftPads(t *testing.T) {
	length := 12

	str := "test"
	padded := utils.LeftPad(str, length)
	assert.Equal(t, len(padded), length)

	padding := string([]rune{2, 2, 2, 2, 2, 2, 2, 2})
	assert.Equal(t, padded, padding+str)
	assert.Equal(t, len(padding), len(padded)-len(str))

	unpadded := utils.Unpad(padded)
	assert.Equal(t, str, unpadded)

	empty := ""
	padded = utils.LeftPad(empty, length)
	assert.Equal(t, length, len(padded))
	unpadded = utils.Unpad(padded)
	assert.Equal(t, empty, unpadded)
}

// TestRightPads ...
func TestRightPads(t *testing.T) {
	length := 12

	str := "test"
	padded := utils.RightPad(str, length)
	assert.Equal(t, len(padded), length)

	unpadded := utils.Unpad(padded)
	assert.Equal(t, str, unpadded)
}

// TestUnpad ...
func TestUnpad(t *testing.T) {
	leftLength := 12
	rightLength := 16

	str := "test"
	padded := utils.LeftPad(str, leftLength)
	padded = utils.RightPad(padded, rightLength)
	assert.Equal(t, len(padded), rightLength)

	unpadded := utils.Unpad(padded)
	assert.Equal(t, str, unpadded)
}
