package encrypter

import (
	"bytes"
	"crumbl/models/signer"
	"errors"
	"math/rand"
	"time"
)

//--- TYPES

// Dispatcher ...
type Dispatcher struct {
	NumberOfSlices int
	Trustees       []signer.Signer
}

//--- METHODS

var (
	combinationsFor3 = [][][]int{
		[][]int{[]int{1, 2}, []int{1, 3}, []int{2, 3}},
		[][]int{[]int{1, 2}, []int{2, 3}, []int{1, 3}},
		[][]int{[]int{1, 3}, []int{2, 3}, []int{1, 2}},
		[][]int{[]int{1, 3}, []int{1, 2}, []int{2, 3}},
		[][]int{[]int{2, 3}, []int{1, 3}, []int{1, 2}},
		[][]int{[]int{2, 3}, []int{1, 2}, []int{1, 3}},
	}
)

// Allocate returns a map of slice index -> trustees to sign, or an error if any.
// It tries to uniformly distribute slices to trustees so that no trustee sign all slices and all slices are at least signed twice if possible.
// Nota: the first slice (index 0) is reserved for data owners, so it should not be allocated.
func (d *Dispatcher) Allocate() (map[int][]signer.Signer, error) {
	allocation := make(map[int][]signer.Signer)
	numberOfTrustees := len(d.Trustees)
	switch numberOfTrustees {
	case 1:
		// All slices must be signed by the single trustee
		for i := 1; i < d.NumberOfSlices; i++ {
			allocation[i] = []signer.Signer{d.Trustees[0]}
		}
	case 2:
		// Slices should all be in double but first and last
		for i := 1; i < d.NumberOfSlices; i++ {
			if i == 1 {
				allocation[i] = []signer.Signer{d.Trustees[0]}
			} else if i == d.NumberOfSlices-1 {
				allocation[i] = []signer.Signer{d.Trustees[1]}
			} else {
				allocation[i] = []signer.Signer{d.Trustees[0], d.Trustees[1]}
			}
		}
	case 3:
		// Slices must be allocated to n-1 trustees at most, and no trustee can have it all
		rand.Seed(time.Now().UnixNano())
		chosen := rand.Intn(len(combinationsFor3))
		for i := 0; i < 3; i++ {
			idx := combinationsFor3[chosen][i]
			allocation[i+1] = []signer.Signer{d.Trustees[idx[0]-1], d.Trustees[idx[1]-1]}
		}
	default:
		err := errors.New("wrong number of trustees")
		return nil, err
	}
	return allocation, nil
}

func contains(signers []signer.Signer, item signer.Signer) bool {
	for _, s := range signers {
		if s.EncryptionAlgorithm == item.EncryptionAlgorithm &&
			bytes.Equal(s.PrivateKey, item.PrivateKey) &&
			bytes.Equal(s.PublicKey, item.PublicKey) {
			return true
		}
	}
	return false
}
