package obfuscator_test

import (
	"crumbl/obfuscator"
	"crumbl/utils"
	"testing"

	"gotest.tools/assert"
)

// TestObfuscatorApply ...
func TestObfuscatorApply(t *testing.T) {
	obfuscated, err := obfuscator.Obfuscator{
		Key:    obfuscator.DEFAULT_KEY_STRING,
		Rounds: obfuscator.DEFAULT_ROUNDS,
	}.Apply("Edgewhere")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, utils.ToHex(obfuscated), "3d7c0a0f51415a521054")
}

// TestObfuscatorUnapply ...
func TestObfuscatorUnapply(t *testing.T) {
	obfuscated, _ := utils.FromHex("3d7c0a0f51415a521054")
	deobfuscated, err := obfuscator.Obfuscator{
		Key:    obfuscator.DEFAULT_KEY_STRING,
		Rounds: obfuscator.DEFAULT_ROUNDS,
	}.Unapply(obfuscated)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, deobfuscated, "Edgewhere")
}

// TestAdd ...
func TestAdd(t *testing.T) {
	added1, err := obfuscator.Add("a", "b")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, added1, "Ã")

	added2, err := obfuscator.Add("ab", "cd")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, added2, "ÄÆ")
}

// TestExtract ...
func TestExtract(t *testing.T) {
	o := obfuscator.Obfuscator{
		Key: "abcd",
	}

	ext1 := obfuscator.Extract(string(o.Key), 1, 2)
	assert.Equal(t, ext1, "bc")

	ext2 := obfuscator.Extract(string(o.Key), 7, 6)
	assert.Equal(t, ext2, "dabcda")
}

// TestRound tests that a change of one bit in the source changes all bits in the result of one round
func TestRound(t *testing.T) {
	o := obfuscator.Obfuscator{
		Key: obfuscator.DEFAULT_KEY_STRING,
	}
	data1 := []byte{1, 0, 0, 0, 0, 0, 0, 0}
	round1, err := o.Round(string(data1), 0)
	if err != nil {
		t.Fatal(err)
	}
	bytes1 := []byte(round1)
	data2 := []byte{1, 1, 0, 0, 0, 0, 0, 0}
	round2, err := o.Round(string(data2), 0)
	if err != nil {
		t.Fatal(err)
	}
	bytes2 := []byte(round2)
	for i := 0; i < len(bytes1); i++ {
		assert.Assert(t, bytes1[i] != bytes2[i])
	}
}

// TestSplit ...
func TestSplit(t *testing.T) {
	str := "half1half2"
	parts, err := obfuscator.Split(str)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, parts[0], "half1")
	assert.Equal(t, parts[1], "half2")
}

// TestXor ...
func TestXor(t *testing.T) {
	xor1 := obfuscator.Xor("a", "b")
	assert.Equal(t, []rune(xor1)[0], rune(3))

	xor2 := obfuscator.Xor("ab", "cd")
	assert.DeepEqual(t, []rune(xor2), []rune{2, 6})
}
