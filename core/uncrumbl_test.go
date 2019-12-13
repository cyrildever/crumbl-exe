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
	crumbled := "580fb8a91f05833200dea7d33536aaec9d7ceb256a9858ee68e330e126ba409d0000a8BA5LudBtwkchppK/K9baKtkXybam/B9xmtE5VmfsKGa5qzdNQdL0UQ34eT3khNlUwcM5TkD/encZSYBz+TdIi9b8p7IigJWEHvC5ONkWla1VnxAs6Y0Krjf6q0iZAE0OtXBiaP/p3JPz9cYaWQdXLhUkTHtSbtbW0omZaQ==0100a8BPS6VX1+7XNfytep5H64DpRPi5ODvW+ViMykJey9VlATWi3zA2nbLSK81gUHtDtkJqA9zTLs62VA/jJQqr/rWd3kWCoJFrYd49iQGEkVqv66Z8+IzufmrRywAeEZqRspDVnBXU4hP+U6Mo3kWuQDIaiq2DoB9BQh2YUZfg==020158cs0kKolHuf20OJJ5TLspHXndQ9avYRPfHeWolLgzyu/RhS6domJMVK8aKqyOmayZGoqDUTG/KjIWULG2XsInd34MrUFJyh6l6wJGbzy8czcbapKtEIf+tYc6sILsKDNlji0jhoMK4wZQBkdlDjQb8lMmpi51TEavUM9Qi5fpJb9ur7ChwR7kNNRsNeyt5c+mckSPDEuGMYYLDKxGk3EYLjPr1lSBUDKHpcIBXSc4QvEdhD4cGRXLlauNI+3Ru8RrwlSHUjb6ykxCHhyQOQ3nzuznHS9TmCaUBWHI9YpCU6ZWzHP0H42te1Mb+0faBuVoafe2Oxh3RnsdY9Iwoku5Mg==.1"

	verificationHash, _ := crypto.Hash([]byte(ref), crypto.DEFAULT_HASH_ENGINE)

	// 1- As trustees
	var uncrumbs [][]byte
	uTrustee1 := core.Uncrumbl{
		Crumbled:         crumbled,
		VerificationHash: "580fb8a91f05833200dea7d33536aaec9d7ceb256a9858ee68e330e126ba409d",
		Signer: signer.Signer{
			EncryptionAlgorithm: "ecies",
			PublicKey:           trustee1_pubkey,
			PrivateKey:          trustee1_privkey,
		},
	}
	uncrumb1, err := uTrustee1.Process()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, string(uncrumb1), "580fb8a91f05833200dea7d33536aaec9d7ceb256a9858ee68e330e126ba409d%01AgICAgKWqJ/v0/4=.1") // This shall be returned by the trustee
	uncrumbs = append(uncrumbs, uncrumb1)

	uTrustee2 := core.Uncrumbl{
		Crumbled:         crumbled,
		VerificationHash: "580fb8a91f05833200dea7d33536aaec9d7ceb256a9858ee68e330e126ba409d",
		Signer: signer.Signer{
			EncryptionAlgorithm: "rsa",
			PublicKey:           trustee2_pubkey,
			PrivateKey:          trustee2_privkey,
		},
	}
	uncrumb2, err := uTrustee2.Process()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, string(uncrumb2), "580fb8a91f05833200dea7d33536aaec9d7ceb256a9858ee68e330e126ba409d%02AgICAgKEEqTinyo=.1") // This shall be returned by the trustee
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
			EncryptionAlgorithm: "ecies",
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
