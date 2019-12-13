package core

import (
	"crumbl/crypto"
	"crumbl/decrypter"
	"crumbl/encrypter"
	"crumbl/models/signer"
	"crumbl/obfuscator"
	"crumbl/utils"
	"errors"
	"fmt"
	"os"
	"strings"
)

//--- TYPES

// Uncrumbl ...
type Uncrumbl struct {
	Crumbled         string
	Slices           []decrypter.Uncrumb
	VerificationHash string
	Signer           signer.Signer
	IsOwner          bool
}

//--- METHODS

// Process ...
func (u *Uncrumbl) Process() ([]byte, error) {
	return u.doUncrumbl()
}

// ToFile ...
func (u Uncrumbl) ToFile(filename string) error {
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	uncrumbled, err := u.doUncrumbl()
	if err != nil {
		return err
	}
	// Add newline
	uncrumbled = append(uncrumbled, []byte("\n")...)
	_, err = f.Write(uncrumbled)
	if err != nil {
		return err
	}
	return nil
}

// ToStdOut ...
func (u *Uncrumbl) ToStdOut() error {
	uncrumbled, err := u.doUncrumbl()
	if err != nil {
		return err
	}
	fmt.Println(string(uncrumbled))
	return nil
}

// doUncrumbl is a multi-step process involving at least an owner or any necessary trustees to recover all crumbs depending on the number of signing parties.
// Eventually, the owner will be the only one able to actually get the original source data in clear.
//
// On an operational stand-point, the process would be as follows:
// 1) The owner sends the crumbled string to all trustees;
// 2) Each trustee decrypts his crumbs and send them back to the owner as partial uncrumbs;
// 3) The owner decrypts his own crumb and add it to the other partial uncrumbs to get the original source fully deciphered.
//
// The uncrumbled result would either be:
// - the fully-deciphered data, ie. the original source normally;
// - partial uncrumbs to use as arguments in another call to the Uncrumbl (by the data owner).
// The latter will be in the following format: <verificationHash><uncrumbs ...>.<version>, each uncrumb starting with the partial prefix,
// the verification hash being prefixed for tracking purpose, and the version at the end after a dot.
func (u *Uncrumbl) doUncrumbl() (uncrumbled []byte, err error) {
	// 1- Parse
	parts := strings.SplitN(u.Crumbled, ".", 2)
	if parts[1] != VERSION {
		err = errors.New("incompatible version: " + parts[1])
		return
	}

	verificationHash := parts[0][0:crypto.DEFAULT_HASH_LENGTH]
	if u.VerificationHash != verificationHash {
		fmt.Fprintln(os.Stderr, "WARNING - incompatible input verification hash with crumbl")
	}

	var crumbs []encrypter.Crumb
	crumbsStr := parts[0][crypto.DEFAULT_HASH_LENGTH:]
	for len(crumbsStr) > 0 {
		nextLen, e := utils.HexToInt(crumbsStr[2:6])
		if e != nil {
			err = e
			return
		}
		nextCrumb := crumbsStr[:nextLen+6]
		crumb, e := encrypter.ToCrumb(nextCrumb)
		if e != nil {
			err = e
			return
		}
		crumbs = append(crumbs, crumb)
		crumbsStr = crumbsStr[nextLen+6:]
	}

	// 2- Decrypt crumbs
	uncrumbs := make(map[int]decrypter.Uncrumb)
	indexSet := make(map[int]bool)
	for _, crumb := range crumbs {
		if !indexSet[crumb.Index] {
			indexSet[crumb.Index] = true
		}
		uncrumb, e := decrypter.Decrypt(crumb, u.Signer)
		if e == nil {
			if _, found := uncrumbs[uncrumb.Index]; !found {
				uncrumbs[uncrumb.Index] = uncrumb
			}
		}
	}

	// 3- Add passed uncrumbs
	for _, uncrumb := range u.Slices {
		if _, found := uncrumbs[uncrumb.Index]; !found {
			uncrumbs[uncrumb.Index] = uncrumb
		}
	}

	// 4- Determine output
	hasAllUncrumbs := false
	if len(indexSet) == len(uncrumbs) {
		hasAllUncrumbs = true
	}
	if u.IsOwner && !hasAllUncrumbs {
		fmt.Fprintln(os.Stderr, "WARNING - missing crumbs to fully uncrumbl as data owner: only partial uncrumbs will be returned")
	}
	if hasAllUncrumbs {
		// Owner may recover fully-deciphered data
		collector := decrypter.Collector{
			Map:              uncrumbs,
			NumberOfSlices:   len(indexSet),
			VerificationHash: verificationHash,
			HashEngine:       crypto.DEFAULT_HASH_ENGINE,
		}

		// 5a- Deofbuscate
		obfuscated, e := collector.ToObfuscated()
		if e != nil {
			err = e
			return
		}
		obfuscator := obfuscator.Obfuscator{
			Key:    obfuscator.DEFAULT_KEY_STRING,
			Rounds: obfuscator.DEFAULT_ROUNDS,
		}
		deobfuscated, e := obfuscator.Unapply(obfuscated)
		if e != nil {
			err = e
			return
		}

		// 6a- Check
		if !collector.Check([]byte(deobfuscated)) {
			fmt.Fprintln(os.Stderr, "WARNING - source has not checked verification hash") // TODO Change it as an error?
		}

		// 7a- Return uncrumbled data, ie. original source normally
		uncrumbled = []byte(deobfuscated)
	} else {
		// Trustee only could return his own uncrumbs

		// 5b- Build partial uncrumbs
		var partialUncrumbs string
		for _, uncrumb := range uncrumbs {
			partialUncrumbs += uncrumb.String()
		}

		// 6b- Add verification hash prefix
		uncrumbled = []byte(verificationHash + partialUncrumbs + "." + VERSION)
	}

	return
}
