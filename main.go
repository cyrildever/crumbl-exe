package main

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

/** Usage:
 *
 *	To create a crumbled e-mail:
 *	`./crumbl -c -out theCrumbl.dat --owner-keys ecies:myKey.pub --signer-keys ecies:edgewhere.pub,rsa:"C:\keys\trustee.pub" cdever@edgewhere.fr`
 *
 *	To extract a crumbled data as the data owner:
 *	`./crumbl -x -out myEmails.txt --owner-keys ecies:myKey.pub --owner-secret myKey.sk -vh <hash> <crumbled> <uncrumbs ...>`
 *	or (if using an input file for the crumbl):
 *	`./crumbl -x -in theCrumbl.dat -out myEmails.txt --owner-keys ecies:myKey.pub --owner-secret myKey.sk -vh <hash> <uncrumbs ...>`
 *
 *	To decrypt crumbs as a signer:
 *	`./crumbl -x -out myUncrumbs.txt --signer-keys ecies:edgewhere.pub --signer-secret edgewhere.sk <crumbled>`
 *
 *	As of the latest version, the library only processes one crumbl at a time.
 */
func main() {
	// Define all flags
	flag.Bool("c", false, "create a crumbled string from source")
	flag.Bool("x", false, "extract crumbl(s)")
	input := flag.String("in", "", "file to read an existing crumbl from (WARNING: do not add the crumbl string in the command-line arguments too)")
	output := flag.String("out", "", "file to save result to")

	ownerKeys := flag.String("owner-keys", "", "comma-separated list of colon-separated encryption algorithm prefix and filepath to public key of owner(s)")
	signerKeys := flag.String("signer-keys", "", "comma-separated list of colon-separated encryption algorithm prefix and filepath to public key of trusted signer(s)")

	ownerSecret := flag.String("owner-secret", "", "filepath to the private key of the owner")
	signerSecret := flag.String("signer-secret", "", "filepath to the private key of the trusted signer")

	hash := flag.String("vh", "", "optional verification hash of the data")

	flag.Parse()

	// Get data
	data := flag.Args()
	if len(data) == 0 {
		if *input == "" {
			check(errors.New("invalid data: not enough arguments and/or no input file to use"))
		} else {
			// TODO Add multiple-line handling (using one crumbl per line in input file)
			content, err := ioutil.ReadFile(*input)
			check(err)
			data = utils.RegexSplit(string(content), "\\s+")
		}
	} else {
		// Any data in an input file should be prepended to the data from the command-line arguments
		if *input != "" {
			// In this case where there are arguments and an input file, there's no possible multiline handling
			tmp := data
			content, err := ioutil.ReadFile(*input)
			check(err)
			data = utils.RegexSplit(string(content), "\\s+")
			data = append(data, tmp...)
		}
	}

	// Check operation: create or extract, ie. crumbl or uncrumbl
	create := isFlagPassed("c")
	extract := isFlagPassed("x")
	if !create && !extract {
		check(errors.New("invalid operation: you must set -c or -x flag"))
	}
	if create && extract {
		check(errors.New("invalid flags: cannot create and extract at the same time"))
	}

	// Get algorithm and keys
	ownersMap := make(map[string]string)
	for _, tuple := range strings.Split(*ownerKeys, ",") {
		if tuple != "" {
			parts := strings.SplitN(tuple, ":", 2)
			algo := parts[0]
			path := parts[1]
			if path != "" {
				if fileExists(path) {
					key, err := ioutil.ReadFile(path)
					check(err)
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

	for _, tuple := range strings.Split(*signerKeys, ",") {
		if tuple != "" {
			parts := strings.SplitN(tuple, ":", 2)
			algo := parts[0]
			path := parts[1]
			if path != "" {
				if fileExists(path) {
					key, err := ioutil.ReadFile(path)
					check(err)
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
	if len(ownersMap) == 0 && (create || (extract && len(signersMap) == 0)) {
		check(errors.New("missing public key for the data owner"))
	}
	if len(signersMap) == 0 && (create || (extract && len(ownersMap) == 0)) {
		check(errors.New("missing public keys for trusted signers"))
	}

	// Check data
	if extract && *hash == "" {
		logWarning("verification hash is missing")
	}
	if len(data) == 0 {
		check(errors.New("no data to use"))
	}

	if create {
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

		crumbl := core.Crumbl{
			Source:     data[0],
			HashEngine: crypto.DEFAULT_HASH_ENGINE,
			Owners:     owners,
			Trustees:   trustees,
		}
		if *output == "" {
			err := crumbl.ToStdOut()
			check(err)
			os.Exit(0)
		}
		err := crumbl.ToFile(*output)
		check(err)
	}
	if extract {
		var user signer.Signer
		hasSigner := false
		isOwner := false
		if *ownerSecret != "" && fileExists(*ownerSecret) {
			if len(ownersMap) != 1 {
				check(errors.New("too many public keys for a data owner"))
			}
			sk, err := ioutil.ReadFile(*ownerSecret)
			check(err)
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
		if !hasSigner && *signerSecret != "" && fileExists(*signerSecret) {
			if len(signersMap) != 1 {
				check(errors.New("too many public keys for a single uncrumbler"))
			}
			sk, err := ioutil.ReadFile(*signerSecret)
			check(err)
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
			check(errors.New("invalid keys: no signer was detected"))
		}

		// TODO Add multiple-line handling (using one crumbl per line in input file)
		var uncrumbs []decrypter.Uncrumb
		if len(data) > 1 {
			for _, u := range data[1:] {
				parts := strings.SplitN(u, ".", 2)
				if parts[1] != core.VERSION {
					logWarning("wrong version for uncrumb: " + u)
					continue
				}
				vh := parts[0][:crypto.DEFAULT_HASH_LENGTH]
				if vh == *hash {
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
			Crumbled:         data[0],
			Slices:           uncrumbs,
			VerificationHash: *hash,
			Signer:           user,
			IsOwner:          isOwner,
		}
		if *output == "" {
			err := uncrumbl.ToStdOut()
			check(err)
			os.Exit(0)
		}
		err := uncrumbl.ToFile(*output)
		check(err)
	}
}

func check(e error) {
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

func isFlagPassed(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func logWarning(msg string) {
	if msg != "" {
		_, fn, line, _ := runtime.Caller(1)
		fmt.Fprintf(os.Stderr, "WARNING - %v [%s:%d]\n", msg, fn, line)
	}
}
