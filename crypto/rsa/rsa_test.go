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

	// see 'crumb-js/test/src/typescript/crypto/rsa/index.spec.ts' test
	fromTypescript := core.Base64("Y7MqItzPFiWIgyhzXNqllmZnaIT1N82kMBfExUv0XrJMrXLRfp/60zSZJbcSIWxXxqqCpW99bcjFtadzveMUaf/T8DvHyXmJXVtOb28ep9mzSoIkyveGxIKZ1347A9kQ2FIzbNlC4UH3ooROu+BXHw/VpaYZCOcupO2RqXC/6OLYi8g02uZQZiIbnkrx/jOXDK/HyQabhb24y+7i53QTROonJUXQE2cE+Q7AIFN7mOZR718dqWu2jGllGFeE5nABreTG6ySqzvVOisPrTqlojXHHe/StCwp8R/oP+cmQN2M1lvzMxFOE26pTNEU1oiJCWBV07aoXZofz/g8hKDL1xg==")
	decrypted, err = rsa.Decrypt(fromTypescript.Decoded(), sk)
	if err != nil {
		t.Fatal(err)
	}
	assert.DeepEqual(t, ref, decrypted)
}
