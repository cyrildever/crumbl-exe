package test_test

import (
	"strings"
	"testing"

	"github.com/cyrildever/crumbl-exe/core"
	"github.com/cyrildever/crumbl-exe/crypto"
	"github.com/cyrildever/crumbl-exe/models/signer"
	utls "github.com/cyrildever/go-utls/common/utils"
	"gotest.tools/assert"
)

// TestMain ...
func TestMain(t *testing.T) {
	src := "cdever@edgewhere.fr"
	hasheredSrc32 := "580fb8a91f05833200dea7d33536aaec" // The first 32 characters of the hasheredSrc are common to any crumbl with the same content

	bpk, _ := utls.FromHex("04b7e6c755d79c8fee7c37ab64c04f0724d069dac025b79008873c660779cab9f5daa9371ee59427be04fed51006bfa86c4278339e1e10a1af7e49424e5836d6be")
	epk, _ := utls.FromHex("04af9f910f3a4d9bf826dacdb113cc3e03bb3f23eebd2a93fcefae527a88905b6923ecd95d4b2071c09300ccd4455fe8e6b026bef470cc1674a5f406ca43ed575d")
	owners := []signer.Signer{{
		EncryptionAlgorithm: crypto.ECIES_ALGORITHM,
		PublicKey:           epk,
	}, {
		EncryptionAlgorithm: crypto.ECIES_ALGORITHM,
		PublicKey:           bpk,
	}}

	t1, _ := utls.FromHex("0443d97cac07353fa20eb3a4ed9d84c7710906189273332c33f3a3482fa25fcbaf2fd5af8fcc48c0296f65071df4c8a562df60a2fa011c47c5db857187ccde8851")
	t2, _ := utls.FromHex("0431042c2f4df1eee9271e937adbce1905bf3e6dd691bd3ed1b1523c67915e2069c930bc9599f34c1df54cca897f9c58c9d3096cfc70eb6ffd005d6bcfcb066c1f")
	t3, _ := utls.FromHex("045e82c8f55688cb23928a024209dfe77920bebe890df483a8b27a2b8251ec90ff94ffd313c2a9361f6cebd2a7ab33ce63d4c7635f71db782218ea85fafedb64c6")
	trustees := []signer.Signer{{
		EncryptionAlgorithm: crypto.ECIES_ALGORITHM,
		PublicKey:           t1,
	}, {
		EncryptionAlgorithm: crypto.ECIES_ALGORITHM,
		PublicKey:           t2,
	}, {
		EncryptionAlgorithm: crypto.ECIES_ALGORITHM,
		PublicKey:           t3,
	}}

	crumbl := core.Crumbl{
		Source:     src,
		HashEngine: crypto.DEFAULT_HASH_ENGINE,
		Owners:     owners,
		Trustees:   trustees,
	}
	crumbled, err := crumbl.Process()
	if err != nil {
		t.Fatal("Unable to process crumbl", "error", err)
	}
	assert.Assert(t, crumbled != "")
	assert.Assert(t, strings.HasPrefix(crumbled, hasheredSrc32))
	// fmt.Printf("SUCCESS\nsrc=%s\ncrumbled=%s\n", crumbl.Source, crumbled)
	// assert.Assert(t, false)
}
