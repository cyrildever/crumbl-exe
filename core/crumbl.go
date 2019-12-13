package core

import (
	"crumbl/crypto"
	"crumbl/encrypter"
	"crumbl/models/signer"
	"crumbl/obfuscator"
	"crumbl/slicer"
	"crumbl/utils"
	"fmt"
	"os"
	"strings"
)

const (
	// VERSION ...
	VERSION = "1" // TODO Change when necessary (change of hash algorithm, modification of string structure, etc.)
)

//--- TYPES

// Crumbl ...
type Crumbl struct {
	Source     string
	HashEngine string
	Owners     []signer.Signer
	Trustees   []signer.Signer
}

//--- METHODS

// Process ...
func (c *Crumbl) Process() (string, error) {
	return c.doCrumbl()
}

// ToFile save the crumbl to file, eventually appending it to an already filled file
func (c *Crumbl) ToFile(filename string) error {
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	crumbled, err := c.doCrumbl()
	if err != nil {
		return err
	}
	// Add newline and write
	_, err = f.Write([]byte(crumbled + "\n"))
	if err != nil {
		return err
	}
	fmt.Printf("SUCCESS - crumbl successfully saved to %v\n", filename)
	return nil
}

// ToStdOut writes the crumbl to stdout
func (c *Crumbl) ToStdOut() error {
	crumbled, err := c.doCrumbl()
	if err != nil {
		return err
	}
	fmt.Println(crumbled)
	return nil
}

// doCrumbl build the actual crumbled string which would be composed of:
// - the hash of the source (in hexadecimal);
// - the concatenation of the stringified encrypted crumbs;
// - a dot followed by the version number of the Crumb&trade; engine used.
func (c *Crumbl) doCrumbl() (crumbled string, err error) {
	// 1-Obfuscate
	obfuscated, err := obfuscator.Obfuscator{
		Key:    obfuscator.DEFAULT_KEY_STRING,
		Rounds: obfuscator.DEFAULT_ROUNDS,
	}.Apply(c.Source)
	if err != nil {
		return
	}

	// 2-Slice
	numberOfSlices := 1 + min(len(c.Trustees), slicer.MAX_SLICES) // Owners only sign the first slice
	deltaMax := slicer.GetDeltaMax(len(obfuscated), numberOfSlices)
	slices, err := slicer.Slicer{
		NumberOfSlices: numberOfSlices,
		DeltaMax:       deltaMax,
	}.Apply(utils.LeftPad(string(obfuscated), slicer.MIN_INPUT_SIZE))
	if err != nil {
		return
	}

	// 3-Encrypt
	var crumbs []encrypter.Crumb
	for _, owner := range c.Owners {
		crumb, e := encrypter.Encrypt(slices[0], 0, owner)
		if e != nil {
			err = e
			return
		}
		crumbs = append(crumbs, crumb)
	}
	dispatcher := encrypter.Dispatcher{
		NumberOfSlices: numberOfSlices,
		Trustees:       c.Trustees,
	}
	allocation, err := dispatcher.Allocate()
	if err != nil {
		return
	}
	for i, trustees := range allocation {
		for _, trustee := range trustees {
			crumb, e := encrypter.Encrypt(slices[i], i, trustee)
			if e != nil {
				err = e
				return
			}
			crumbs = append(crumbs, crumb)
		}
	}

	// 4-Hash the source string
	hSrc, err := crypto.Hash([]byte(c.Source), crypto.DEFAULT_HASH_ENGINE)
	if err != nil {
		return
	}

	// 5- Finalize the output string
	var stringifiedCrumbs []string
	for _, c := range crumbs {
		stringifiedCrumbs = append(stringifiedCrumbs, c.String())
	}
	crumbled = utils.ToHex(hSrc) + strings.Join(stringifiedCrumbs, "") + "." + VERSION

	return
}

func min(x, y int) int {
	if x < y {
		return x
	}
	return y
}
