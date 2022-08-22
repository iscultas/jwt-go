package jwa

import "crypto"

type Algorithm interface {
	String() string
}

type Signer interface {
	Algorithm
	Sign(token []byte, key any) ([]byte, error)
}

type Verifier interface {
	Algorithm
	Verify(unsignedToken, signature []byte, key any) (bool, error)
}

type signingAlgorithm struct {
	name string
	hash crypto.Hash
}

func (algorithm *signingAlgorithm) String() string {
	return algorithm.name
}
