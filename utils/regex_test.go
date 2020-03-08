package utils_test

import (
	"testing"

	"github.com/edgewhere/crumbl-exe/utils"

	"gotest.tools/assert"
)

// TestRegexSplit ...
func TestRegexSplit(t *testing.T) {
	str := "first   second"
	data := utils.RegexSplit(str, "\\s+")
	assert.Equal(t, len(data), 2)
}
