package utils_test

import (
	"crumbl/utils"
	"testing"

	"gotest.tools/assert"
)

// TestRegexSplit ...
func TestRegexSplit(t *testing.T) {
	str := "first   second"
	data := utils.RegexSplit(str, "\\s+")
	assert.Equal(t, len(data), 2)
}
