package utils

import (
	"regexp"
)

// RegexSplit splits a string using a regular expression.
// see https://stackoverflow.com/questions/4466091/split-string-using-regular-expression-in-go
func RegexSplit(text string, delimeter string) []string {
	reg := regexp.MustCompile(delimeter)
	indexes := reg.FindAllStringIndex(text, -1)
	laststart := 0
	result := make([]string, len(indexes)+1)
	for i, element := range indexes {
		result[i] = text[laststart:element[0]]
		laststart = element[1]
	}
	result[len(indexes)] = text[laststart:]
	return result
}
