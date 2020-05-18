package obfuscator

import (
	"errors"

	"github.com/edgewhere/crumbl-exe/crypto"
	"github.com/edgewhere/crumbl-exe/utils"
)

const (
	// DEFAULT_KEY_STRING ...
	DEFAULT_KEY_STRING = "8ed9dcc1701c064f0fd7ae235f15143f989920e0ee9658bb7882c8d7d5f05692" // SHA-256("crumbl by Edgewhere")

	// DEFAULT_ROUNDS ...
	DEFAULT_ROUNDS = 10
)

// Obfuscator ...
type Obfuscator struct {
	Key    string
	Rounds int
}

// Apply transforms the passed string to an obfuscated byte array through a Feistel cipher
func (o Obfuscator) Apply(data string) (obfuscated []byte, err error) {
	if len(data)%2 == 1 {
		data = utils.LeftPad(data, len(data)+1)
	}
	// Apply the Feistel cipher
	parts, err := Split(data)
	if err != nil {
		return
	}
	for i := 0; i < o.Rounds; i++ {
		rnd, _ := o.Round(parts[1], i)
		tmp := Xor(parts[0], rnd)
		parts = []string{parts[1], tmp}
	}
	obfuscated = []byte(parts[0] + parts[1])
	return
}

// Unapply transforms the passed obfuscated byte array to a deobfuscated string through a Feistel cipher
func (o Obfuscator) Unapply(obfuscated []byte, verificationHash string) (deobfuscated string, err error) {
	if len(string(obfuscated))%2 != 0 {
		found := false
		for i := 0; i < len(obfuscated); i++ {
			begin := string(obfuscated)[:i]
			end := string(obfuscated)[i:]
			attempt := begin + string(utils.LEFT_PADDING_CHARACTER) + end
			if d, err := o.doUnapply([]byte(attempt)); err == nil {
				hashedData, e := crypto.Hash([]byte(d), crypto.DEFAULT_HASH_ENGINE)
				if e != nil {
					continue
				}
				if utils.ToHex(hashedData) == verificationHash {
					deobfuscated = d
					found = true
					break
				}
			}
		}
		if !found {
			err = errors.New("invalid obfuscated data")
		}
		return
	}
	return o.doUnapply(obfuscated)
}

func (o Obfuscator) doUnapply(obfuscated []byte) (deobfuscated string, err error) {
	// Apply the Feistel cipher
	parts, err := Split(string(obfuscated))
	if err != nil {
		err = errors.New("cannot split obfuscated data")
		return
	}
	a := parts[1]
	b := parts[0]
	var tmp string
	for i := 0; i < o.Rounds; i++ {
		rnd, _ := o.Round(b, o.Rounds-i-1)
		tmp = Xor(a, rnd)
		a = b
		b = tmp
	}
	deobfuscated = b + a
	deobfuscated = utils.Unpad(deobfuscated)
	return
}
