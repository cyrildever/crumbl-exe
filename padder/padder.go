package padder

import (
	"errors"
	"fmt"
	"math"
	"os"

	"github.com/edgewhere/crumbl-exe/utils"
)

// The 'padder' module adds left padding to a passed byte array with Apply(), and reverse the operation with Unapply().
//
// If you simply want to left pad to make the length of a data even, pass the length of the data as second parameter
// and `true` as third parameter to Apply(), eg. ```
// 		padded, _, err := padder.Apply(data, len(data), true)
// ```
// Otherwise, pass the maximum length of all data as second parameter (normally greater than or equal to the length of the data)
// and `false` as the third, eg. ```
// 		padded, _, err := padder.Apply(data, maxSliceLength, false)
// ```
//
// The Unapply() operation will raise a WARNING if the data is not of even length and the prepend size doesn't seem to be respected.

const (
	// ALTERNATE_PADDING_CHARACTER_1 ...
	ALTERNATE_PADDING_CHARACTER_1 rune = 4 // Unicode U+0004: end-of-transmission

	// ALTERNATE_PADDING_CHARACTER_2 ...
	ALTERNATE_PADDING_CHARACTER_2 rune = 5 // Unicode U+0005: enquiry

	// NO_PADDING_CHARACTER ...
	NO_PADDING_CHARACTER rune = 0 // rune zero value is int32(0)

	// PREPEND_SIZE is the minimum number of prepended padding character in the padded result
	PREPEND_SIZE = 2
)

// Apply left pads the passed data (generally a slice) making it at least (PREPEND_SIZE + length) bytes long;
// if the 'buildEven' parameter is set to `true`, it doesn't take PREPEND_SIZE into account and
// only adds padding bytes to the left up to the passed length.
func Apply(slice []byte, length int, buildEven bool) (padded []byte, padChar rune, err error) {
	if len(slice) == 0 {
		err = errors.New("empty slice")
		return
	}
	if length < 1 {
		err = errors.New("max slice length too short")
		return
	}
	if buildEven && length != len(slice) && length%2 != 0 {
		err = errors.New("wished length is not even")
		return
	}

	// An already even slice doesn't need processing when buildEven is set to `true` and minimum length is reached
	if buildEven && len(slice)%2 == 0 && len(slice) >= length {
		padded = slice
		return
	}

	// 1 - Choose padding character
	firstByte := slice[0]
	lastByte := slice[len(slice)-1]
	var pc rune
	if firstByte == byte(utils.LEFT_PADDING_CHARACTER) {
		if lastByte == byte(ALTERNATE_PADDING_CHARACTER_1) {
			pc = ALTERNATE_PADDING_CHARACTER_2
		} else {
			pc = ALTERNATE_PADDING_CHARACTER_1
		}
	} else {
		if lastByte == byte(utils.LEFT_PADDING_CHARACTER) {
			if firstByte == byte(ALTERNATE_PADDING_CHARACTER_1) {
				pc = ALTERNATE_PADDING_CHARACTER_2
			} else {
				pc = ALTERNATE_PADDING_CHARACTER_1
			}
		} else {
			pc = utils.LEFT_PADDING_CHARACTER
		}
	}

	// 2 - Define filling delta
	delta := int(math.Max(0, float64(length-len(slice))))
	if buildEven {
		if (len(slice)+delta)%2 != 0 {
			delta++
		}
	} else {
		delta += PREPEND_SIZE
	}

	// 3 - Do pad
	var p []byte
	for i := 0; i < delta; i++ {
		p = append(p, byte(pc))
	}
	p = append(p, slice...)

	return p, pc, nil
}

// Unapply removes the left padding from the passed padded data.
func Unapply(padded []byte) (slice []byte, padChar rune, err error) {
	if len(padded) < 2 {
		err = errors.New("invalid padded data: data too short")
		return
	}

	// 1 - Detect padding character
	pc := padded[0]
	if pc != byte(utils.LEFT_PADDING_CHARACTER) &&
		pc != byte(ALTERNATE_PADDING_CHARACTER_1) &&
		pc != byte(ALTERNATE_PADDING_CHARACTER_2) {
		if len(padded)%2 == 0 {
			// It's probably a data that would have been padded only if it were of odd length,
			// hence probably padded with 'buildEven' set to `true`
			slice = padded
		} else {
			err = errors.New("invalid padded data: wrong padding")
		}
		return
	}

	// 2 - Test prepend sequence
	if len(padded) < PREPEND_SIZE+1 {
		err = errors.New("invalid data: padded data too short")
		return
	}
	if padded[PREPEND_SIZE-1] != pc && len(padded)%2 == 1 {
		fmt.Fprintln(os.Stderr, "WARNING - possibly wrong padding: data is not of even length and prepend size wasn't respected") // TODO Change to error?
	}

	// 3 - Do unpad
	unpadded := padded
	for len(unpadded) > 0 && unpadded[0] == pc {
		unpadded = unpadded[1:]
	}
	if len(unpadded) == 0 {
		err = errors.New("invalid padded data: all pad chars")
		return
	}

	return unpadded, rune(pc), nil
}
