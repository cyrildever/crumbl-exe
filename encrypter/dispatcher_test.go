package encrypter_test

import (
	"bytes"
	"crumbl/encrypter"
	"crumbl/models/signer"
	"testing"

	"gotest.tools/assert"
)

// TestAllocate ...
func TestAllocate(t *testing.T) {
	d := encrypter.Dispatcher{
		NumberOfSlices: 4,
		Trustees: []signer.Signer{
			signer.Signer{PublicKey: []byte{1}},
			signer.Signer{PublicKey: []byte{2}},
			signer.Signer{PublicKey: []byte{3}},
		},
	}
	allocation, err := d.Allocate()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, len(allocation[1]), 2)
	assert.Assert(t, !bytes.Equal(allocation[1][0].PublicKey, allocation[1][1].PublicKey))
	assert.Equal(t, len(allocation[2]), 2)
	assert.Assert(t, !bytes.Equal(allocation[2][0].PublicKey, allocation[2][1].PublicKey))
	assert.Equal(t, len(allocation[3]), 2)
	assert.Assert(t, !bytes.Equal(allocation[3][0].PublicKey, allocation[3][1].PublicKey))
}
