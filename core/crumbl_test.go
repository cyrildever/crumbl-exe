package core_test

import (
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/cyrildever/crumbl-exe/core"
	"github.com/cyrildever/crumbl-exe/crypto"
	"github.com/cyrildever/crumbl-exe/models/signer"
	"github.com/cyrildever/crumbl-exe/utils"
)

var (
	owner1_pubkey, _    = utils.FromHex("04e315a987bd79b9f49d3a1c8bd1ef5a401a242820d52a3f22505da81dfcd992cc5c6e2ae9bc0754856ca68652516551d46121daa37afc609036ab5754fe7a82a3") // see '../crypto/ecies/keys/owner1.pub'
	owner1_privkey, _   = utils.FromHex("b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a36e0cf7c0bf85dc1130b8a0")                                                                   // see '../crypto/ecies/keys/owner1.sk'
	trustee1_pubkey, _  = utils.FromHex("040c96f971c0edf58fe4afbf8735581be05554a8a725eae2b7ad2b1c6fcb7b39ef4e7252ed5b17940a9201c089bf75cb11f97e5c53333a424e4ebcca36065e0bc0") // see '../crypto/ecies/keys/trustee1.pub'
	trustee1_privkey, _ = utils.FromHex("80219e4d24caf16cb4755c1ae85bad02b6a3efb1e3233379af6f2cc1a18442c4")                                                                   // see '../crypto/ecies/keys/trustee1.sk'
	trustee2_pubkey, _  = ioutil.ReadFile("../crypto/rsa/keys/trustee2.pub")
	trustee2_privkey, _ = ioutil.ReadFile("../crypto/rsa/keys/trustee2.sk")
	trustee3_pubkey, _  = utils.FromHex("04e8d931172dd09cff868ec36235512cfedfef632f81d50d7272490c5cfe8efffe3cfcde7f0eba4759456489d3735bf7510a7c4478e8bd9c37873afd0b798693bd")
	trustee3_privkey, _ = utils.FromHex("8bf49f4ccb80e659c65a7bf127a292d30584d0b9f9bf1cd84bee425eb2a3ab9e")
)

// TestCrumbl ...
func TestCrumbl(t *testing.T) {
	source := "cdever@edgewhere.fr"

	c1 := core.Crumbl{
		Source:     source,
		HashEngine: crypto.DEFAULT_HASH_ENGINE,
		Owners: []signer.Signer{
			signer.Signer{
				EncryptionAlgorithm: crypto.ECIES_ALGORITHM,
				PublicKey:           owner1_pubkey,
				PrivateKey:          owner1_privkey,
			},
		},
		Trustees: []signer.Signer{
			signer.Signer{
				EncryptionAlgorithm: crypto.ECIES_ALGORITHM,
				PublicKey:           trustee1_pubkey,
				PrivateKey:          trustee1_privkey,
			},
			signer.Signer{
				EncryptionAlgorithm: crypto.RSA_ALGORITHM,
				PublicKey:           trustee2_pubkey,
				PrivateKey:          trustee2_privkey,
			},
		},
	}
	crumbled, err := c1.Process()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(crumbled)
	//assert.Assert(t, false)

	// Equivalent to core/crumbl.spec.ts
	c2 := core.Crumbl{
		Source:     source,
		HashEngine: crypto.DEFAULT_HASH_ENGINE,
		Owners: []signer.Signer{
			signer.Signer{
				EncryptionAlgorithm: crypto.ECIES_ALGORITHM,
				PublicKey:           owner1_pubkey,
				PrivateKey:          owner1_privkey,
			},
		},
		Trustees: []signer.Signer{
			signer.Signer{
				EncryptionAlgorithm: crypto.ECIES_ALGORITHM,
				PublicKey:           trustee1_pubkey,
				PrivateKey:          trustee1_privkey,
			},
			signer.Signer{
				EncryptionAlgorithm: crypto.ECIES_ALGORITHM,
				PublicKey:           trustee3_pubkey,
				PrivateKey:          trustee3_privkey,
			},
		},
	}
	crumbled, err = c2.Process()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(crumbled)
	// assert.Assert(t, false)
}
