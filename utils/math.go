package utils

import (
	"errors"
)

// EuclideanDivision returns the integer tuple (quotient, remainder) from the division of the past integers
func EuclideanDivision(numerator, denominator int) (quotient, remainder int, err error) {
	if denominator == 0 {
		err = errors.New("division by zero") // TODO typed error
		return
	}
	quotient = numerator / denominator
	remainder = numerator % denominator
	return
}
