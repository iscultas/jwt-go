package jwa

import (
	"crypto"
)

type none struct {
	signingAlgorithm
}

var none_ = &none{signingAlgorithm{"none", crypto.MD4}}

func None() *none { return none_ }

func (algorithm *none) Sign(token []byte, jwk any) ([]byte, error) {
	return []byte{}, nil
}

func (algorithm *none) Verify(unsignedToken, signature []byte, key any) (bool, error) {
	return true, nil
}
