package core_test

import (
	"crumbl/core"
	"crumbl/crypto"
	"crumbl/decrypter"
	"crumbl/models/signer"
	"crumbl/utils"
	"strings"
	"testing"

	"gotest.tools/assert"
)

// TestUncrumbl ...
func TestUncrumbl(t *testing.T) {
	ref := "cdever@edgewhere.fr"
	crumbled := "580fb8a91f05833200dea7d33536aaec9d7ceb256a9858ee68e330e126ba409d0000a8BJM2I8mS/bkFNdZOATg8jHsQbzYp4o5rTqYWkf/pqgvkH7a4OijBxy86W1y2J+pB525jYO4iBuig2JswBdNv++8dkb0GcSXT873M0I5Xma9oM83eHXihOF2rqnqWN/RNZPwJSM23DcCj/xyVs1FK5jWVMGxtMLttIN7vqg==010158KbcQ6boXhkGdXR97+UwSHvt12wEwkVa57e+2m+66sTu32luP00cWET2gb01tgNZYjU621U7u4RI6fmz5kkyTSZtjPJ5wXISTf2wOBv5cY94LvgYoyMFKP9J3mGbPgAKGGsIdY4GCQBx6+Gi7VzfuNxdP1YHAPqcpKXPWiY+nmqYhT7eZVZlmNF1UmkMbgrneYglenmKxWSyUA6P7yMj3LrhlKekWAPdWpMLzRftLh1oH5e2KHkz7Wyh9eYOCKXlQ4sUUm8o3i0Inann41wL0KGaNajPU1RP0M9n3/Zil1/T+ZZcNJgSlQh1mxVKX1ztBRqYNUy+pqDat1qq6ED5r5A==0200a8BIIMyYgouCq7ZVy7S1kRJUl1Lg+aQMHoNeo7SauKwsy//XZ5rJOF4FrYMXmPpu0pf7nwCgAgk6Iv9IQK+WXsKpDE+QazdPpYFtxm4/1qi8qnzG1Wp/9Lf5nFTozacHqghz2e7XkaO1qyLNfmzimpsm6aw/lhEsd+djJ8KA==.1"

	verificationHash, _ := crypto.Hash([]byte(ref), crypto.DEFAULT_HASH_ENGINE)

	// 1- As trustees
	var uncrumbs [][]byte
	uTrustee1 := core.Uncrumbl{
		Crumbled:         crumbled,
		VerificationHash: "580fb8a91f05833200dea7d33536aaec9d7ceb256a9858ee68e330e126ba409d",
		Signer: signer.Signer{
			EncryptionAlgorithm: crypto.ECIES_ALGORITHM,
			PublicKey:           trustee1_pubkey,
			PrivateKey:          trustee1_privkey,
		},
	}
	uncrumb1, err := uTrustee1.Process()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, string(uncrumb1), "580fb8a91f05833200dea7d33536aaec9d7ceb256a9858ee68e330e126ba409d%02AgICAgICAgkYUkI=.1") // This shall be returned by the trustee
	uncrumbs = append(uncrumbs, uncrumb1)

	uTrustee2 := core.Uncrumbl{
		Crumbled:         crumbled,
		VerificationHash: "580fb8a91f05833200dea7d33536aaec9d7ceb256a9858ee68e330e126ba409d",
		Signer: signer.Signer{
			EncryptionAlgorithm: crypto.RSA_ALGORITHM,
			PublicKey:           trustee2_pubkey,
			PrivateKey:          trustee2_privkey,
		},
	}
	uncrumb2, err := uTrustee2.Process()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, string(uncrumb2), "580fb8a91f05833200dea7d33536aaec9d7ceb256a9858ee68e330e126ba409d%01AgICBFUDDk4PXEc=.1") // This shall be returned by the trustee
	uncrumbs = append(uncrumbs, uncrumb2)

	// 2- As an owner
	var fromTrustees []decrypter.Uncrumb
	for _, u := range uncrumbs {
		parts := strings.SplitN(string(u), ".", 2)
		if parts[1] != core.VERSION {
			t.Fatalf("invalid version: %s\n", parts[1])
		}
		us := parts[0][crypto.DEFAULT_HASH_LENGTH:]
		uncs := strings.Split(us, decrypter.PARTIAL_PREFIX)
		for _, unc := range uncs {
			if unc != "" {
				uncrumb, err := decrypter.ToUncrumb(unc)
				if err != nil {
					continue
				}
				fromTrustees = append(fromTrustees, uncrumb)
			}
		}
	}

	uOwner := core.Uncrumbl{
		Crumbled:         crumbled,
		Slices:           fromTrustees,
		VerificationHash: utils.ToHex(verificationHash),
		Signer: signer.Signer{
			EncryptionAlgorithm: crypto.ECIES_ALGORITHM,
			PublicKey:           owner1_pubkey,
			PrivateKey:          owner1_privkey,
		},
		IsOwner: true,
	}
	uncrumbled, err := uOwner.Process()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, ref, string(uncrumbled))
}
