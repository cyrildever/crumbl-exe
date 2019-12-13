package main

import (
	"crumbl/core"
	"errors"
	"flag"
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

	// Check operation: create or extract, ie. crumbl or uncrumbl
	var mode core.CrumblMode
	create := isFlagPassed("c")
	extract := isFlagPassed("x")
	if !create && !extract {
		core.Check(errors.New("invalid operation: you must set -c or -x flag"))
	}
	if create && extract {
		core.Check(errors.New("invalid flags: cannot create and extract at the same time"))
	}
	if create {
		mode = core.CREATION
	}
	if extract {
		mode = core.EXTRACTION
	}

	// Launch worker
	worker := core.CrumblWorker{
		Mode:             mode,
		Input:            input,
		Output:           output,
		OwnerKeys:        ownerKeys,
		OwnerSecret:      ownerSecret,
		SignerKeys:       signerKeys,
		SignerSecret:     signerSecret,
		VerificationHash: hash,
		Data:             data,
	}
	worker.Process()
}

//--- utilities

func isFlagPassed(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}
