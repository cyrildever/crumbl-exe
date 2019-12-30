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

	// For RSA key of 2048 bits (256 bytes), using the SHA-512 hash of 64 bytes long with OAEP,
	// the RSA padding will be 2 * 64 + 2 = 130 bytes.
	// Hence, the max length of the data would be 256 - 130 = 126 bytes.
	veryLongStr := "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrs"
	assert.Assert(t, len(veryLongStr) > 256-(2*64+2)) // As this public key is a 2048-bits RSA key

	_, err = rsa.Encrypt([]byte(veryLongStr), pk)
	assert.Equal(t, err.Error(), "crypto/rsa: message too long for RSA public key size")
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

	// see 'crumb-jar/src/test/scala/io/crumbl/crypto/rsa/RSASpecs.scala' test
	fromScala := core.Base64("S9MEYmEsIurjcMNnN/wSPDF9G/cpeFzmkD7utv2X3dqBo0SfI0IpduuAypcVg/d2qW/tWbKT1uxAUesqcAWn8flPQ2uECrMBdXl/rIGDQYUsA813LsGTCscUfvglyTWTRKDuYRUK91fJb6jsdfgg3onFDBkofdVg2EqQcyRxMK93RS8bJ86lN3K0Y0WgdqHstxwlJAwRPzJb+4MFLLdZlEtsWik0ys7zM9f3uvm34rSbeUg8sin63/1wAAMdcui9xDcf2bmwyO5vvDt9aAzBA3kK/BqPMBDe0+i8kzq3xOxtWfjZy8ZZB0tewNP9bkI0SNHikzHJPrd3fxwtdoeYLw==")
	decrypted, err = rsa.Decrypt(fromScala.Decoded(), sk)
	if err != nil {
		t.Fatal(err)
	}
	assert.DeepEqual(t, ref, decrypted)
}
