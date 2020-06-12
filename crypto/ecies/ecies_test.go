package ecies_test

import (
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/cyrildever/crumbl-exe/crypto/ecies"
	"github.com/cyrildever/crumbl-exe/models/core"
	"github.com/cyrildever/crumbl-exe/utils"

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

	cipheredScala := core.Base64("BEhU7cwY4QhZgTyEZ3vXoUUvwaX5a8vfCyyYDwIFvqOlLwa0iV2q6FikFQed7um8EbJRFh10P/zpqJsxJ2MGS+yjzut/85BxDHJf7Mp/kkST+bnRX1FVj1MIP+OERtPY7MZr6iq6XWQmO8S2qn4MGZAXdP3R9048eyk=")
	decrypted, err = ecies.Decrypt(cipheredScala.Bytes(), sk, pk)
	if err != nil {
		t.Fatal(err)
	}
	assert.DeepEqual(t, ref, decrypted)
}
