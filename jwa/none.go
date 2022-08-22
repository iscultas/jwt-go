package jwa

import "hash"

type noneHash struct {
	sum []byte
}

func (noneHash_ *noneHash) Write(p []byte) (n int, err error) {
	return 0, nil
}

func (noneHash_ *noneHash) Sum(b []byte) []byte {
	return noneHash_.sum
}

func (noneHash_ *noneHash) Reset() {}

func (noneHash_ *noneHash) Size() int {
	return 0
}

func (noneHash_ *noneHash) BlockSize() int {
	return 0
}

func newNoneHash() hash.Hash {
	return &noneHash{sum: []byte{}}
}

func None() Signature {
	return &signature{"none", newNoneHash()}
}
