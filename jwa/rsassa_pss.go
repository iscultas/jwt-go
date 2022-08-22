package jwa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
)

type rsassaPSS struct {
	signingAlgorithm
}

var (
	ps256 = &rsassaPSS{signingAlgorithm{"PS256", crypto.SHA256}}
	ps384 = &rsassaPSS{signingAlgorithm{"PS384", crypto.SHA384}}
	ps512 = &rsassaPSS{signingAlgorithm{"PS512", crypto.SHA512}}
)

func PS256() *rsassaPSS { return ps256 }

func PS384() *rsassaPSS { return ps384 }

func PS512() *rsassaPSS { return ps512 }

func (algorithm *rsassaPSS) Sign(token []byte, key any) ([]byte, error) {
	hash := algorithm.hash.New()

	if _, err := hash.Write(token); err != nil {
		return nil, err
	}

	return rsa.SignPSS(rand.Reader, key.(*rsa.PrivateKey), algorithm.hash, hash.Sum(nil), nil)
}

func (algorithm *rsassaPSS) Verify(unsignedToken, signature []byte, key any) (bool, error) {
	hash := algorithm.hash.New()
	if _, err := hash.Write(unsignedToken); err != nil {
		return false, err
	}

	err := rsa.VerifyPSS(key.(*rsa.PublicKey), algorithm.hash, hash.Sum(nil), signature, nil)
	return err == nil, err
}
