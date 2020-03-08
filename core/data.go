package core

import (
	"errors"
	"strings"

	"github.com/edgewhere/crumbl-exe/crypto"
	"github.com/edgewhere/crumbl-exe/decrypter"
	"github.com/edgewhere/crumbl-exe/encrypter"
)

// GetCrumbs returns the underlying slices of the passed crumbled string
func GetCrumbs(crumbled string) (crumbs []encrypter.Crumb, err error) {
	parts := strings.SplitN(crumbled, ".", 2)
	if parts[1] != VERSION {
		err = errors.New("incompatible version: " + parts[1])
		return
	}
	crumbsStr := parts[0][crypto.DEFAULT_HASH_LENGTH:]
	cs, err := parse(crumbsStr)
	if err != nil {
		return
	}
	return cs, nil
}

// GetUncrumbs returns the underlying uncrumbs fromt the passed partialUncrumbs string
func GetUncrumbs(partialUncrumb string) (uncrumbs []decrypter.Uncrumb, err error) {
	if !strings.Contains(partialUncrumb, decrypter.PARTIAL_PREFIX) {
		err = errors.New("not a partialUncrumb string")
		return
	}
	parts := strings.SplitN(partialUncrumb, ".", 2)
	if parts[1] != VERSION {
		err = errors.New("incompatible version: " + parts[1])
		return
	}
	us := parts[0][crypto.DEFAULT_HASH_LENGTH:]
	uncs := strings.Split(us, decrypter.PARTIAL_PREFIX)
	for _, unc := range uncs {
		if unc != "" {
			uncrumb, err := decrypter.ToUncrumb(unc)
			if err != nil {
				continue
			}
			uncrumbs = append(uncrumbs, uncrumb)
		}
	}
	return
}
