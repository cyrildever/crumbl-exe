package decrypter

import (
	"errors"
	"fmt"
	"strings"

	"github.com/edgewhere/crumbl-exe/models/core"
	"github.com/edgewhere/crumbl-exe/slicer"
	"github.com/edgewhere/crumbl-exe/utils"
)

const (
	// PARTIAL_PREFIX ...
	PARTIAL_PREFIX = "%"
)

//--- TYPES

// Uncrumb holds the deciphered slice and its index.
type Uncrumb struct {
	Deciphered core.Base64
	Index      int
}

//--- METHODS

// String transforms the Uncrumb into its stringified representation.
// The construct is as follows:
// - the uncrumb's partial prefix;
// - the following two characters are the hexadecimal representation of the index, ie. utils.IntToHex(Index);
// - the base64-encoded deciphered slice.
func (u *Uncrumb) String() string {
	return PARTIAL_PREFIX + fmt.Sprintf("%02x", u.Index) + u.Deciphered.String()
}

// ToSlice ...
func (u *Uncrumb) ToSlice() slicer.Slice {
	return slicer.Slice(string(u.Deciphered.Decoded()))
}

// ToUncrumb ...
func ToUncrumb(unparsed string) (u Uncrumb, err error) {
	idx, dec, err := Parse(unparsed)
	if err != nil {
		return
	}
	u = Uncrumb{
		Deciphered: core.Base64(dec),
		Index:      idx,
	}
	return
}

// Parse ...
func Parse(unparsed string) (index int, dec string, err error) {
	if len(unparsed) < 7 {
		err = errors.New("unparsed string too short")
		return
	}
	if strings.HasPrefix(unparsed, PARTIAL_PREFIX) {
		unparsed = unparsed[len(PARTIAL_PREFIX):]
	}
	idxHex := unparsed[:2]
	idx, err := utils.HexToInt(idxHex)
	if err != nil {
		return
	}
	d := unparsed[2:]
	if !core.IsBase64String(d) {
		err = errors.New("not a base64-encoded string")
		return
	}
	index = idx
	dec = d
	return
}
