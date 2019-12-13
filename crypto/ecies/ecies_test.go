package ecies_test

import (
	"crumbl/crypto/ecies"
	"crumbl/models/core"
	"crumbl/utils"
	"fmt"
	"io/ioutil"
	"testing"

	"gotest.tools/assert"
)

// TestEncrypt ...
func TestEncrypt(t *testing.T) {
	pub, _ := ioutil.ReadFile("keys/owner1.pub")
	pk, _ := utils.FromHex(string(pub))
	msg := []byte("Edgewhere")

	crypted, err := ecies.Encrypt(msg, pk)
	fmt.Println(core.ToBase64(crypted).String())
	if err != nil {
		t.Fatal(err)
	}
	//assert.Assert(t, false)
}

func TestDecrypt(t *testing.T) {
	pub, _ := ioutil.ReadFile("keys/owner1.pub")
	pk, _ := utils.FromHex(string(pub))
	priv, _ := ioutil.ReadFile("keys/owner1.sk")
	sk, _ := utils.FromHex(string(priv))
	ref := []byte("Edgewhere")

	ciphered := core.Base64("BB76SDcT8FvJbVVs5J7jECfGGOk1T38wx1z8U9erOsyh8JOnYnVtHk7NXbB/FAj8nUpkUPSHBRIVx6+8ChdQ6L7mKSL099Odnomtl+0GMMd6mVOKj7r8Mt6klrSOiHUaq0wsATDThYTl8lGdPwsECQQT8waX+KOWjfo=")
	decrypted, err := ecies.Decrypt(ciphered.Bytes(), sk, pk)
	if err != nil {
		t.Fatal(err)
	}
	assert.DeepEqual(t, ref, decrypted)
}
