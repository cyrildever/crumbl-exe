package rsa_test

import (
	"crumbl/crypto/rsa"
	"crumbl/models/core"
	"fmt"
	"io/ioutil"
	"testing"

	"gotest.tools/assert"
)

// TestEncrypt ...
func TestEncrypt(t *testing.T) {
	pk, _ := ioutil.ReadFile("keys/trustee2.pub")
	msg := []byte("Edgewhere")

	crypted, err := rsa.Encrypt(msg, pk)
	fmt.Println(core.ToBase64(crypted).String())
	if err != nil {
		t.Fatal(err)
	}
}

// TestDecrypt ...
func TestDecrypt(t *testing.T) {
	ref := []byte("Edgewhere")
	sk, _ := ioutil.ReadFile("keys/trustee2.sk")
	ciphered := core.Base64("QkordMcNgkQEV3NU5d2zcfmPfmUHnj/bXg7TpcgQqQzpuUhoExNpjNarNoZ+HMwRAzhtqzyIoaFERsTRi8lMiehX9+dvEZNqqNvCt5huRkgwW0g+FHYi2TTdgmCLuKJoBwtsun17o69HeoK9nmG6UXvocx/OPzUJEgHIVggW3ibk4j/uvCtCPiL44IV86JsOMaJewbKEXNMGGWuKsN25c93vr6tS+B4YhR5VFWc93ENdnK+3SIwcOGfNaJLunmRN96AsdDLU9J3Bsl93JH8xSnW1Q8paKqCliFxHXOAvsWbcGRMO2FfDXLCf+bBBZLxQrfSg7O+tn1WQfe0UVjY7Sw==")

	decrypted, err := rsa.Decrypt(ciphered.Decoded(), sk)
	if err != nil {
		t.Fatal(err)
	}
	assert.DeepEqual(t, ref, decrypted)
}
