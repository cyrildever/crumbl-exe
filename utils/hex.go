package utils

import (
	"encoding/hex"
	"fmt"
	"strconv"
)

// FromHex tries to convert an hexadecimal representation of a value to its corresponding byte array
func FromHex(input string) ([]byte, error) {
	return hex.DecodeString(input)
}

// ToHex converts a byte array to its string representation in hexadecimal
func ToHex(input []byte) string {
	return hex.EncodeToString(input)
}

// IntToHex converts an integer to its string representation in hexadecimal
func IntToHex(input int) string {
	return fmt.Sprintf("%x", input)
}

// HexToInt tries to convert an hexadecimal representation of an integer to its value
func HexToInt(input string) (number int, err error) {
	i, err := strconv.ParseInt(input, 16, 32)
	if err != nil {
		return
	}
	number = int(i)
	return
}
