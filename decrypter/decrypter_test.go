package decrypter_test

import (
	"crumbl/decrypter"
	"crumbl/encrypter"
	"crumbl/models/core"
	"crumbl/models/signer"
	"crumbl/utils"
	"testing"

	"gotest.tools/assert"
)

// TestDecrypter ...
func TestDecrypter(t *testing.T) {
	ref := "AgICAmoMD1lNU0g="
	ciphered := "BFimUWhXgnYhTPo7CAQfxBcctdESBrpB/0ECaTPArpxNFr9hLUIJ2nLEwxm2F6xFu8d5sgA9QJqI/Y/PVDem9IxuiFJsAU+4CeUVKYw/nSwwt4Nco8EGBgPY03ekxLD2T3Zp0Z+jowTPtCGHwtuwYE+INwjQgti0Io6E1Q=="

	owner1_priv := []byte("b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a36e0cf7c0bf85dc1130b8a0")
	owner1_sk, _ := utils.FromHex(string(owner1_priv))
	owner1_pub := []byte("04e315a987bd79b9f49d3a1c8bd1ef5a401a242820d52a3f22505da81dfcd992cc5c6e2ae9bc0754856ca68652516551d46121daa37afc609036ab5754fe7a82a3")
	owner1_pk, _ := utils.FromHex(string(owner1_pub))
	owner1 := signer.Signer{
		EncryptionAlgorithm: "ecies",
		PrivateKey:          owner1_sk,
		PublicKey:           owner1_pk,
	}
	crumb := encrypter.Crumb{
		Encrypted: core.Base64(ciphered),
		Index:     2,
		Length:    len(ciphered),
	}
	found, err := decrypter.Decrypt(crumb, owner1)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, ref, found.Deciphered.String())

	trustee1_priv := []byte("80219e4d24caf16cb4755c1ae85bad02b6a3efb1e3233379af6f2cc1a18442c4")
	trustee1_sk, _ := utils.FromHex(string(trustee1_priv))
	trustee1_pub := []byte("040c96f971c0edf58fe4afbf8735581be05554a8a725eae2b7ad2b1c6fcb7b39ef4e7252ed5b17940a9201c089bf75cb11f97e5c53333a424e4ebcca36065e0bc0")
	trustee1_pk, _ := utils.FromHex(string(trustee1_pub))
	trustee1 := signer.Signer{
		EncryptionAlgorithm: "ecies",
		PrivateKey:          trustee1_sk,
		PublicKey:           trustee1_pk,
	}
	_, err = decrypter.Decrypt(crumb, trustee1)
	assert.Assert(t, err.Error() == "ecies: invalid message")
}
