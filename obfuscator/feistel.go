package obfuscator

import (
	"crypto/sha256"
	"errors"
	"math"
	"strings"

	"github.com/cyrildever/crumbl-exe/utils"
)

// Round is the function applied at each round of the obfuscation process to the right side of the Feistel cipher
func (o Obfuscator) Round(item string, number int) (processed string, err error) {
	// First, add passed item to key extraction
	addition, err := Add(item, Extract(o.Key, number, len(item)))
	if err != nil {
		return
	}
	// Then, hash the addition
	h := sha256.New()
	h.Write([]byte(addition))
	// Finally, keep what's needed
	processed = Extract(utils.ToHex(h.Sum(nil)), number, len(item))
	return
}

// Add adds two strings in the sense that each charCode/rune are added
func Add(s1 string, s2 string) (added string, err error) {
	if len(s1) != len(s2) {
		err = errors.New("to be added, strings must be of the same length ")
		return
	}
	for i := 0; i < len(s1); i++ {
		added = added + string(rune(s1[i])+rune(s2[i]))
	}
	return
}

// Extract returns an extraction of the passed string of the desired length from the passed start index.
// If the desired length is too long, the key string is repeated.
func Extract(from string, startIndex int, desiredLength int) string {
	startIndex = startIndex % len(from)
	lengthNeeded := startIndex + desiredLength
	return strings.Repeat(from, int(math.Ceil(float64(lengthNeeded)/float64(len(from)))))[startIndex:lengthNeeded]
}

// Split splits a string in two equal parts
func Split(s string) (parts []string, err error) {
	if len(s)%2 != 0 {
		err = errors.New("invalid string length: cannot be split")
		return
	}
	half := len(s) / 2
	return []string{s[:half], s[half:]}, nil
}

// Xor function XOR two strings in the sense that each charCode/rune are xored
func Xor(item1 string, item2 string) string {
	n := len(item1)
	b := make([]byte, n)
	for i := 0; i < n; i++ {
		b[i] = item1[i] ^ item2[i]
	}
	return string(b)
}
