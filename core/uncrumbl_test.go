package core_test

import (
	"strings"
	"testing"

	"github.com/edgewhere/crumbl-exe/core"
	"github.com/edgewhere/crumbl-exe/crypto"
	"github.com/edgewhere/crumbl-exe/decrypter"
	"github.com/edgewhere/crumbl-exe/models/signer"
	"github.com/edgewhere/crumbl-exe/utils"

	"gotest.tools/assert"
)

// TestUncrumbl ...
func TestUncrumbl(t *testing.T) {
	ref := "cdever@edgewhere.fr"
	crumbled := "580fb8a91f05833200dea7d33536aaec995cb2ed83f99c68d99a3f114d5b93e20000a8BCBZyOlhxIaxeQ/wa+HTf8o6EV/pvnNfS+Bc3zcYsbSvU0nK8asl058RYeSg+ierk8siW1os/GGVI9S9jG+j3S9iPrVAImWQBa8TmK7FKJZZCGadmvgXwOwYk13tnhzRztn8XgRBuD3Sz1pl/2NwLrnf6Gzd65S6R3atXg==0100a8BG5EjHp5w+jIsOOS+ioCU6kZVx1AzLQx/IxmuaBsVLuPd2bPvH5cZBB92MDS1YnapeSsHLQ4sQT1oy7jT9Mj50Ncjqy0Tqo87H6l9OTPrqj/elN/v9fxpFd7r1zxiljAM31tLyvYCqfGmAhqnyscWOOPA83MmY1jZNAy+A==020158SWu9PrmVHwZqNfBvxAeXa85Q11/l3jUevcfqujYIR1Xw+PzaHjqSAca1zkSLtSvgwnIQKiKt/ug6ox/bpF3QU4wIDg/VFzG0pzE6IgWlWzWYbl4gRlBiGSXQT5MCu4zJvlmusH7UqANYZlGhNdapkJqalMV3ir06RXIIS3ffWvUxdprU6mP5MQqfYj6creGfBxXc7SSyLgL3znPFSb+ddz4TVbc7+sbAjS0LCPrYXm6bBxx7KVuJMjIQmWNqObD5mtiLLTyhmhLvNJ21zgz+pB6sRVq61hT7fKJ5TFsUNkkKQk/HmOld8N38usv1xdZQKRrIoQ5m+C3pMKbhyaS8TA==.1"

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
	assert.Equal(t, string(uncrumb1), "580fb8a91f05833200dea7d33536aaec9d7ceb256a9858ee68e330e126ba409d%01AgIEVQMOTg9cRwk=.1") // This shall be returned by the trustee
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
	assert.Equal(t, string(uncrumb2), "580fb8a91f05833200dea7d33536aaec9d7ceb256a9858ee68e330e126ba409d%02AgICAgICAgIYUkI=.1") // This shall be returned by the trustee
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
