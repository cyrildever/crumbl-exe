package utils

import (
	"strings"
)

const (
	// LEFT_PADDING_CHARACTER ...
	LEFT_PADDING_CHARACTER rune = 2 // Unicode U+0002: start of text

	// RIGHT_PADDING_CHARACTER ...
	RIGHT_PADDING_CHARACTER rune = 3 // Unicode U+0003: end of text
)

// LeftPad ...
func LeftPad(str string, minLength int) string {
	if len(str) >= minLength {
		return str
	}
	for len(str) < minLength {
		str = string(LEFT_PADDING_CHARACTER) + str
	}
	return str
}

// RightPad ...
func RightPad(str string, minLength int) string {
	if len(str) >= minLength {
		return str
	}
	for len(str) < minLength {
		str = str + string(RIGHT_PADDING_CHARACTER)
	}
	return str
}

// Unpad ...
func Unpad(str string) string {
	if len(str) > 0 {
		for strings.HasPrefix(str, string(LEFT_PADDING_CHARACTER)) {
			str = str[1:]
		}
		for strings.HasSuffix(str, string(RIGHT_PADDING_CHARACTER)) {
			str = str[:len(str)-1]
		}
	}
	return str
}
