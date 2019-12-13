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
	if strings.Contains(str, string(LEFT_PADDING_CHARACTER)) {
		str = strings.Replace(str, string(LEFT_PADDING_CHARACTER), "", len(str))
	}
	if strings.Contains(str, string(RIGHT_PADDING_CHARACTER)) {
		str = strings.Replace(str, string(RIGHT_PADDING_CHARACTER), "", len(str))
	}
	return str
}
