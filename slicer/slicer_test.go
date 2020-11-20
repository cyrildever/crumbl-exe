package slicer_test

import (
	"math/rand"
	"strconv"
	"testing"
	"time"

	"github.com/cyrildever/crumbl-exe/slicer"

	"gotest.tools/assert"
)

// TestSliceApply ...
func TestSliceApply(t *testing.T) {
	s1 := slicer.Slicer{
		NumberOfSlices: 4,
		DeltaMax:       0,
	}
	slices1, err := s1.Apply("11111222223333344444")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, len(slices1), s1.NumberOfSlices)
	assert.Equal(t, slices1[0], slicer.Slice("11111"))
	assert.Equal(t, slices1[1], slicer.Slice("22222"))
	assert.Equal(t, slices1[2], slicer.Slice("33333"))
	assert.Equal(t, slices1[3], slicer.Slice("44444"))

	str2 := "111111111222222222333333333444444444"
	s2 := slicer.Slicer{
		NumberOfSlices: 4,
		DeltaMax:       2,
	}
	slices2, err := s2.Apply(str2)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range slices2 {
		assert.Equal(t, len(s), 13)
	}
	assert.Equal(t, slices2[3], slicer.Slice("44444444")) // It's predictive thanks to the seed
}

// TestSliceUnapply ...
func TestSliceUnapply(t *testing.T) {
	s := slicer.Slicer{
		NumberOfSlices: 4,
		DeltaMax:       0,
	}

	data, err := s.Unapply([]slicer.Slice{
		slicer.Slice("11111"),
		slicer.Slice("22222"),
		slicer.Slice("33333"),
		slicer.Slice("44444"),
	})
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, data, "11111222223333344444")

	// Empty slices
	_, err = s.Unapply([]slicer.Slice{})
	assert.Assert(t, err != nil)
}

// TestGetDeltaMax ...
func TestGetDeltaMax(t *testing.T) {
	dMax := slicer.GetDeltaMax(8, 4)
	assert.Equal(t, dMax, 0)
	dMax = slicer.GetDeltaMax(12, 4)
	assert.Equal(t, dMax, 2)
	dMax = slicer.GetDeltaMax(16, 4)
	assert.Equal(t, dMax, 4)
	dMax = slicer.GetDeltaMax(20, 4)
	assert.Equal(t, dMax, 5)
	dMax = slicer.GetDeltaMax(50, 4)
	assert.Equal(t, dMax, slicer.MAX_DELTA)
}

// TestSeed ...
func TestSeed(t *testing.T) {
	data1 := "ab" // 97 + 98 = 195
	seed1 := slicer.SeedFor(data1)
	assert.Equal(t, seed1, slicer.Seed(195))
}

// TestSlicer should work under heavy load
func TestSlicer(t *testing.T) {
	for i := 1; i < 10000; i++ {
		data := string(strconv.Itoa((rand.New(rand.NewSource(time.Now().UnixNano())).Intn(10)+1)*1e6 + i))
		s := slicer.Slicer{
			NumberOfSlices: 2,
			DeltaMax:       slicer.GetDeltaMax(len(data), 2),
		}
		tmp, err := s.Apply(data)
		if err != nil {
			t.Fatal(err, i, data, []byte(data), tmp)
		}
		found, err := s.Unapply(tmp)
		if err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, data, found)
	}
}
