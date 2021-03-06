package padder_test

import (
	"testing"

	"github.com/cyrildever/crumbl-exe/padder"
	"github.com/cyrildever/crumbl-exe/utils"
	"gotest.tools/assert"
)

// Equivalent to crumbl-js/Padder/index.spec.ts

// TestApply ...
func TestApply(t *testing.T) {
	maxSliceLength := 3
	slice1 := []byte{3, 4, 5}
	padded1, padChar, err := padder.Apply(slice1, maxSliceLength, false)
	if err != nil {
		t.Fatal(err)
	}
	assert.DeepEqual(t, padded1, []byte{2, 2, 3, 4, 5})
	assert.Equal(t, padChar, utils.LEFT_PADDING_CHARACTER)
	assert.Equal(t, len(padded1), maxSliceLength+padder.PREPEND_SIZE)

	slice2 := []byte{6, 7}
	padded2, padChar, _ := padder.Apply(slice2, maxSliceLength, false)
	assert.DeepEqual(t, padded2, []byte{2, 2, 2, 6, 7})
	assert.Equal(t, padChar, utils.LEFT_PADDING_CHARACTER)
	assert.Equal(t, len(padded2), maxSliceLength+padder.PREPEND_SIZE)

	slice3 := []byte{2, 3}
	padded3, padChar, _ := padder.Apply(slice3, maxSliceLength, false)
	assert.DeepEqual(t, padded3, []byte{byte(padChar), byte(padChar), byte(padChar), 2, 3})
	assert.Equal(t, byte(padChar), padded3[0])
	assert.Equal(t, padChar, padder.ALTERNATE_PADDING_CHARACTER_1)
	assert.Assert(t, string(padChar) != string(utils.LEFT_PADDING_CHARACTER))
	assert.Equal(t, len(padded3), maxSliceLength+padder.PREPEND_SIZE)

	slice4 := []byte{2, 4}
	padded4, padChar, _ := padder.Apply(slice4, maxSliceLength, false)
	assert.DeepEqual(t, padded4, []byte{byte(padChar), byte(padChar), byte(padChar), 2, 4})
	assert.Equal(t, byte(padChar), padded4[0])
	assert.Equal(t, padChar, padder.ALTERNATE_PADDING_CHARACTER_2)

	expected := []byte{2, 1, 1, 1}
	slice5 := []byte{1, 1, 1}
	padded5, _, _ := padder.Apply(slice5, len(slice5), true)
	assert.Equal(t, len(padded5), 4)
	assert.DeepEqual(t, padded5, expected)

	wrongSlice := []byte{}
	_, _, err = padder.Apply(wrongSlice, maxSliceLength, false)
	assert.Error(t, err, "empty slice")

	wrongLength := 0
	_, _, err = padder.Apply(slice1, wrongLength, false)
	assert.Error(t, err, "max slice length too short")

	alreadyEvenData := []byte{2, 2}
	padded, _, _ := padder.Apply(alreadyEvenData, len(alreadyEvenData), true)
	assert.DeepEqual(t, alreadyEvenData, padded)

	alreadyEvenButTooShort := []byte{4, 4}
	wishedLength := 4
	padded, _, _ = padder.Apply(alreadyEvenButTooShort, wishedLength, true)
	assert.DeepEqual(t, padded, []byte{2, 2, 4, 4})
	assert.Equal(t, len(padded), wishedLength)

	_, _, err = padder.Apply(slice1, 5, true)
	assert.Error(t, err, "wished length is not even")
}

// TestUnapply ...
func TestUnapply(t *testing.T) {
	padded1 := []byte{2, 2, 3, 4, 5}
	unpadded1, padChar, err := padder.Unapply(padded1)
	if err != nil {
		t.Fatal(err)
	}
	assert.DeepEqual(t, unpadded1, []byte{3, 4, 5})
	assert.Equal(t, padChar, utils.LEFT_PADDING_CHARACTER)

	padded2 := []byte{2, 2, 2}
	_, _, err = padder.Unapply(padded2)
	assert.Error(t, err, "invalid padded data: all pad chars")

	padded3 := []byte{5, 5, 5, 2, 4}
	unpadded3, padChar, _ := padder.Unapply(padded3)
	assert.DeepEqual(t, unpadded3, []byte{2, 4})
	assert.Equal(t, padChar, padder.ALTERNATE_PADDING_CHARACTER_2)

	evenData := []byte{127, 127}
	unpadded4, padChar, err := padder.Unapply(evenData)
	if err != nil {
		t.Fatal(err)
	}
	assert.DeepEqual(t, unpadded4, evenData)
	assert.Equal(t, padChar, padder.NO_PADDING_CHARACTER) // rune zero value

	evenZero := []byte{0, 0}
	unpadded5, padChar, _ := padder.Unapply(evenZero)
	assert.DeepEqual(t, unpadded5, evenZero)
	assert.Equal(t, padChar, padder.NO_PADDING_CHARACTER) // doesn't mean that if has taken zero value as pad character

	wrongPadded := []byte{127, 126, 125}
	_, _, err = padder.Unapply(wrongPadded)
	assert.Error(t, err, "invalid padded data: wrong padding")
}
