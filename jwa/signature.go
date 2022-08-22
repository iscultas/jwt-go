package jwa

import "hash"

type Signature interface {
	Algorithmer
	Sign(payload []byte) []byte
}

type signature struct {
	algorithm
	hash_ hash.Hash
}

func (signAlgorithm_ *signature) Header() map[string]any {
	header := signAlgorithm_.algorithm.Header()
	header["typ"] = "JWT"
	return header
}

func (signAlgorithm_ *signature) Sign(payload []byte) []byte {
	signAlgorithm_.hash_.Write([]byte(payload))
	return signAlgorithm_.hash_.Sum(nil)
}
