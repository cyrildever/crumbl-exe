package client

import (
	"crumbl/core"
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
	Input            string
	Output           string
	OwnerKeys        string
	OwnerSecret      string
	SignerKeys       string
	SignerSecret     string
	VerificationHash string
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
func (w *CrumblWorker) Process(returnResult bool) (result string, err error) {
	// Prepare processing...

	// Check mode
	if w.Mode != CREATION && w.Mode != EXTRACTION {
		err = fmt.Errorf("invalid mode: %s", w.Mode)
		if !Check(err, returnResult) {
			return
		}
	}

	// Build data if need be
	if len(w.Data) == 0 {
		if w.Input == "" {
			err = errors.New("invalid data: not enough arguments and/or no input file to use")
			if !Check(err, returnResult) {
				return
			}
		} else {
			content, e := ioutil.ReadFile(w.Input)
			if !Check(e, returnResult) {
				err = e
				return
			}
			// TODO Add multiple-line handling (using one crumbl per line in input file)
			contentStr := strings.Replace(string(content), "\n", " ", -1)
			w.Data = utils.RegexSplit(contentStr, "\\s+")
		}
	} else {
		// Any data in an input file should be prepended to the data from the command-line arguments
		if w.Input != "" {
			// In this case where there are arguments and an input file, there's no possible multiline handling
			tmp := w.Data
			content, e := ioutil.ReadFile(w.Input)
			if !Check(e, returnResult) {
				err = e
				return
			}
			contentStr := strings.Replace(string(content), "\n", " ", -1)
			w.Data = utils.RegexSplit(contentStr, "\\s+")
			w.Data = append(w.Data, tmp...)
		}
	}

	// Get algorithm and keys
	ownersMap, err := fillMap(w.OwnerKeys, returnResult)
	if !Check(err, returnResult) {
		return
	}
	signersMap, err := fillMap(w.SignerKeys, returnResult)
	if !Check(err, returnResult) {
		return
	}
	if len(ownersMap) == 0 && (w.Mode == CREATION || (w.Mode == EXTRACTION && len(signersMap) == 0)) {
		err = errors.New("missing public key for the data owner")
		if !Check(err, returnResult) {
			return
		}
	}
	if len(signersMap) == 0 && (w.Mode == CREATION || (w.Mode == EXTRACTION && len(ownersMap) == 0)) {
		err = errors.New("missing public keys for trusted signers")
		if !Check(err, returnResult) {
			return
		}
	}

	// Check data
	if w.Mode == EXTRACTION && w.VerificationHash == "" {
		logWarning("verification hash is missing")
	}
	if len(w.Data) == 0 {
		err = errors.New("no data to use")
		if !Check(err, returnResult) {
			return
		}
	}

	// Do processing...
	if w.Mode == CREATION {
		owners := buildSigners(ownersMap)
		trustees := buildSigners(signersMap)
		return w.create(owners, trustees, returnResult)
	}
	if w.Mode == EXTRACTION {
		user, isOwner, e := w.buildUser(ownersMap, signersMap, returnResult)
		if !Check(e, returnResult) {
			err = e
			return
		}
		return w.extract(user, isOwner, returnResult)
	}
	return
}

func (w *CrumblWorker) create(owners []signer.Signer, trustees []signer.Signer, returnResult bool) (result string, err error) {
	crumbl := core.Crumbl{
		Source:     w.Data[0],
		HashEngine: crypto.DEFAULT_HASH_ENGINE,
		Owners:     owners,
		Trustees:   trustees,
	}
	if w.Output == "" {
		res, e := crumbl.ToStdOut()
		if !Check(e, returnResult) {
			err = e
			return
		}
		if returnResult {
			result = res
			return
		}
		os.Exit(0)
	}
	res, e := crumbl.ToFile(w.Output)
	if !Check(e, returnResult) {
		err = e
		return
	}
	if returnResult {
		result = res
	}
	return
}

func (w *CrumblWorker) extract(user signer.Signer, isOwner bool, returnResult bool) (result string, err error) {
	// TODO Add multiple-line handling (using one crumbl per line in input file)
	var uncrumbs []decrypter.Uncrumb
	if len(w.Data) > 1 {
		for _, u := range w.Data[1:] {
			parts := strings.SplitN(u, ".", 2)
			if parts[1] != core.VERSION {
				logWarning("wrong version for uncrumb: " + u)
				continue
			}
			vh := parts[0][:crypto.DEFAULT_HASH_LENGTH]
			if vh == w.VerificationHash {
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

	uncrumbl := core.Uncrumbl{
		Crumbled:         w.Data[0],
		Slices:           uncrumbs,
		VerificationHash: w.VerificationHash,
		Signer:           user,
		IsOwner:          isOwner,
	}
	if w.Output == "" {
		res, e := uncrumbl.ToStdOut()
		if !Check(e, returnResult) {
			err = e
			return
		}
		if returnResult {
			result = res
			return
		}
		os.Exit(0)
	}
	e := uncrumbl.ToFile(w.Output)
	if !Check(e, returnResult) {
		err = e
		return
	}
	return
}

//--- utilities

// Check ...
func Check(e error, returnResult bool) bool {
	if e != nil {
		if returnResult {
			return false
		}
		_, fn, line, _ := runtime.Caller(1)
		fmt.Fprintf(os.Stderr, "ERROR - %v [%s:%d]\n", e, fn, line)
		flag.Usage()
		os.Exit(1)
	}
	return true
}

func buildSigners(withMap map[string]string) []signer.Signer {
	signers := make([]signer.Signer, 0)
	for pk, algo := range withMap {
		pubkey, err := crypto.GetKeyBytes(pk, algo)
		if err != nil {
			logWarning(err.Error())
			continue
		}
		signer := signer.Signer{
			EncryptionAlgorithm: algo,
			PublicKey:           pubkey,
		}
		signers = append(signers, signer)
	}
	return signers
}

func (w *CrumblWorker) buildUser(ownersMap map[string]string, signersMap map[string]string, returnResult bool) (user signer.Signer, isOwner bool, err error) {
	var u signer.Signer
	hasSigner := false
	owns := false
	if w.OwnerSecret != "" && fileExists(w.OwnerSecret) {
		if len(ownersMap) != 1 {
			err = errors.New("too many public keys for a data owner")
			return
		}
		sk, e := ioutil.ReadFile(w.OwnerSecret)
		if e != nil {
			err = e
			return
		}
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
			u = signer.Signer{
				EncryptionAlgorithm: algo,
				PublicKey:           pubkey,
				PrivateKey:          privkey,
			}
			hasSigner = true
			owns = true
			break
		}
	}
	if !hasSigner && w.SignerSecret != "" && fileExists(w.SignerSecret) {
		if len(signersMap) != 1 {
			err = errors.New("too many public keys for a single uncrumbler")
			return
		}
		sk, e := ioutil.ReadFile(w.SignerSecret)
		if e != nil {
			err = e
			return
		}
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
			u = signer.Signer{
				EncryptionAlgorithm: algo,
				PublicKey:           pubkey,
				PrivateKey:          privkey,
			}
			hasSigner = true
			break
		}
	}
	if !hasSigner {
		err = errors.New("invalid keys: no signer was detected")
		return
	}
	user = u
	isOwner = owns
	return
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func fillMap(dataKeys string, returnResult bool) (map[string]string, error) {
	theMap := make(map[string]string)
	for _, tuple := range strings.Split(dataKeys, ",") {
		if tuple != "" {
			parts := strings.SplitN(tuple, ":", 2)
			algo := parts[0]
			path := parts[1]
			if path != "" {
				if fileExists(path) {
					key, e := ioutil.ReadFile(path)
					if !Check(e, returnResult) {
						return nil, e
					}
					if crypto.ExistsAlgorithm(algo) {
						theMap[string(key)] = algo
					} else {
						logWarning("invalid encryption algorithm in " + tuple)
					}
				} else {
					logWarning("invalid file path in " + tuple)
				}
			}
		}
	}
	return theMap, nil
}

func logWarning(msg string) {
	if msg != "" {
		_, fn, line, _ := runtime.Caller(1)
		fmt.Fprintf(os.Stderr, "WARNING - %v [%s:%d]\n", msg, fn, line)
	}
}
