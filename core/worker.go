package core

import (
	"crumbl/crypto"
	"crumbl/decrypter"
	"crumbl/models/signer"
	"crumbl/utils"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"runtime"
	"strings"
)

//--- TYPES

// CrumblWorker ...
type CrumblWorker struct {
	Mode             CrumblMode
	Input            *string
	Output           *string
	OwnerKeys        *string
	OwnerSecret      *string
	SignerKeys       *string
	SignerSecret     *string
	VerificationHash *string
	Data             []string
}

// CrumblMode ...
type CrumblMode string

const (
	// CREATION ...
	CREATION = CrumblMode("crumbl")

	// EXTRACTION ...
	EXTRACTION = CrumblMode("uncrumbl")
)

//--- METHODS

// Process ...
func (w *CrumblWorker) Process() {
	if len(w.Data) == 0 {
		if *w.Input == "" {
			Check(errors.New("invalid data: not enough arguments and/or no input file to use"))
		} else {
			content, err := ioutil.ReadFile(*w.Input)
			Check(err)
			// TODO Add multiple-line handling (using one crumbl per line in input file)
			contentStr := strings.Replace(string(content), "\n", "", -1)
			w.Data = utils.RegexSplit(contentStr, "\\s+")
		}
	} else {
		// Any data in an input file should be prepended to the data from the command-line arguments
		if *w.Input != "" {
			// In this case where there are arguments and an input file, there's no possible multiline handling
			tmp := w.Data
			content, err := ioutil.ReadFile(*w.Input)
			Check(err)
			contentStr := strings.Replace(string(content), "\n", "", -1)
			w.Data = utils.RegexSplit(contentStr, "\\s+")
			w.Data = append(w.Data, tmp...)
		}
	}

	// Get algorithm and keys
	ownersMap := make(map[string]string)
	for _, tuple := range strings.Split(*w.OwnerKeys, ",") {
		if tuple != "" {
			parts := strings.SplitN(tuple, ":", 2)
			algo := parts[0]
			path := parts[1]
			if path != "" {
				if fileExists(path) {
					key, err := ioutil.ReadFile(path)
					Check(err)
					if crypto.ExistsAlgorithm(algo) {
						ownersMap[string(key)] = algo
					} else {
						logWarning("invalid encryption algorithm for owner in " + tuple)
					}
				} else {
					logWarning("invalid file path for owner in " + tuple)
				}
			}
		}
	}
	signersMap := make(map[string]string)

	for _, tuple := range strings.Split(*w.SignerKeys, ",") {
		if tuple != "" {
			parts := strings.SplitN(tuple, ":", 2)
			algo := parts[0]
			path := parts[1]
			if path != "" {
				if fileExists(path) {
					key, err := ioutil.ReadFile(path)
					Check(err)
					if crypto.ExistsAlgorithm(algo) {
						signersMap[string(key)] = algo
					} else {
						logWarning("invalid encryption algorithm for signer in " + tuple)
					}
				} else {
					logWarning("invalid file path for signer in " + tuple)
				}
			}
		}
	}
	if len(ownersMap) == 0 && (w.Mode == CREATION || (w.Mode == EXTRACTION && len(signersMap) == 0)) {
		Check(errors.New("missing public key for the data owner"))
	}
	if len(signersMap) == 0 && (w.Mode == CREATION || (w.Mode == EXTRACTION && len(ownersMap) == 0)) {
		Check(errors.New("missing public keys for trusted signers"))
	}

	// Check data
	if w.Mode == EXTRACTION && *w.VerificationHash == "" {
		logWarning("verification hash is missing")
	}
	if len(w.Data) == 0 {
		Check(errors.New("no data to use"))
	}

	if w.Mode == CREATION {
		var owners []signer.Signer
		for pk, algo := range ownersMap {
			pubkey, err := crypto.GetKeyBytes(pk, algo)
			if err != nil {
				logWarning(err.Error())
				continue
			}
			owner := signer.Signer{
				EncryptionAlgorithm: algo,
				PublicKey:           pubkey,
			}
			owners = append(owners, owner)
		}

		var trustees []signer.Signer
		for pk, algo := range signersMap {
			pubkey, err := crypto.GetKeyBytes(pk, algo)
			if err != nil {
				logWarning(err.Error())
				continue
			}
			trustee := signer.Signer{
				EncryptionAlgorithm: algo,
				PublicKey:           pubkey,
			}
			trustees = append(trustees, trustee)
		}

		crumbl := Crumbl{
			Source:     w.Data[0],
			HashEngine: crypto.DEFAULT_HASH_ENGINE,
			Owners:     owners,
			Trustees:   trustees,
		}
		if *w.Output == "" {
			err := crumbl.ToStdOut()
			Check(err)
			os.Exit(0)
		}
		err := crumbl.ToFile(*w.Output)
		Check(err)
	}
	if w.Mode == EXTRACTION {
		var user signer.Signer
		hasSigner := false
		isOwner := false
		if *w.OwnerSecret != "" && fileExists(*w.OwnerSecret) {
			if len(ownersMap) != 1 {
				Check(errors.New("too many public keys for a data owner"))
			}
			sk, err := ioutil.ReadFile(*w.OwnerSecret)
			Check(err)
			for pk, algo := range ownersMap {
				pubkey, err := crypto.GetKeyBytes(pk, algo)
				if err != nil {
					logWarning(err.Error())
					continue
				}
				privkey, err := crypto.GetKeyBytes(string(sk), algo)
				if err != nil {
					logWarning(err.Error())
					continue
				}
				user = signer.Signer{
					EncryptionAlgorithm: algo,
					PublicKey:           pubkey,
					PrivateKey:          privkey,
				}
				hasSigner = true
				isOwner = true
				break
			}
		}
		if !hasSigner && *w.SignerSecret != "" && fileExists(*w.SignerSecret) {
			if len(signersMap) != 1 {
				Check(errors.New("too many public keys for a single uncrumbler"))
			}
			sk, err := ioutil.ReadFile(*w.SignerSecret)
			Check(err)
			for pk, algo := range signersMap {
				pubkey, err := crypto.GetKeyBytes(pk, algo)
				if err != nil {
					logWarning(err.Error())
					continue
				}
				privkey, err := crypto.GetKeyBytes(string(sk), algo)
				if err != nil {
					logWarning(err.Error())
					continue
				}
				user = signer.Signer{
					EncryptionAlgorithm: algo,
					PublicKey:           pubkey,
					PrivateKey:          privkey,
				}
				hasSigner = true
				break
			}
		}
		if !hasSigner {
			Check(errors.New("invalid keys: no signer was detected"))
		}

		// TODO Add multiple-line handling (using one crumbl per line in input file)
		var uncrumbs []decrypter.Uncrumb
		if len(w.Data) > 1 {
			for _, u := range w.Data[1:] {
				parts := strings.SplitN(u, ".", 2)
				if parts[1] != VERSION {
					logWarning("wrong version for uncrumb: " + u)
					continue
				}
				vh := parts[0][:crypto.DEFAULT_HASH_LENGTH]
				if vh == *w.VerificationHash {
					us := parts[0][crypto.DEFAULT_HASH_LENGTH:]
					uncs := strings.Split(us, decrypter.PARTIAL_PREFIX)
					for _, unc := range uncs {
						if unc != "" {
							uncrumb, err := decrypter.ToUncrumb(unc)
							if err != nil {
								continue
							}
							uncrumbs = append(uncrumbs, uncrumb)
						}
					}
				}
			}
		}

		uncrumbl := Uncrumbl{
			Crumbled:         w.Data[0],
			Slices:           uncrumbs,
			VerificationHash: *w.VerificationHash,
			Signer:           user,
			IsOwner:          isOwner,
		}
		if *w.Output == "" {
			err := uncrumbl.ToStdOut()
			Check(err)
			os.Exit(0)
		}
		err := uncrumbl.ToFile(*w.Output)
		Check(err)
	}
}

//--- utilities

// Check ...
func Check(e error) {
	if e != nil {
		_, fn, line, _ := runtime.Caller(1)
		fmt.Fprintf(os.Stderr, "ERROR - %v [%s:%d]\n", e, fn, line)
		flag.Usage()
		os.Exit(1)
	}
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func logWarning(msg string) {
	if msg != "" {
		_, fn, line, _ := runtime.Caller(1)
		fmt.Fprintf(os.Stderr, "WARNING - %v [%s:%d]\n", msg, fn, line)
	}
}
