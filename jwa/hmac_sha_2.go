package jwa

import (
	"crypto"
	"crypto/hmac"
)

type hmacSHA2 struct {
	signingAlgorithm
}

var (
	hs256 = &hmacSHA2{signingAlgorithm{"HS256", crypto.SHA256}}
	hs384 = &hmacSHA2{signingAlgorithm{"HS384", crypto.SHA384}}
	hs512 = &hmacSHA2{signingAlgorithm{"HS512", crypto.SHA512}}
)

func HS256() *hmacSHA2 { return hs256 }

func HS384() *hmacSHA2 { return hs384 }

func HS512() *hmacSHA2 { return hs512 }

func (algorithm *hmacSHA2) Sign(token []byte, key any) ([]byte, error) {
	hash := hmac.New(algorithm.hash.New, key.([]byte))

	if _, err := hash.Write(token); err != nil {
		return nil, err
	}
	return hash.Sum(nil), nil
}

func (algorithm *hmacSHA2) Verify(unsignedToken, signature []byte, key any) (bool, error) {
	hash := hmac.New(algorithm.hash.New, key.([]byte))
	if _, err := hash.Write(unsignedToken); err != nil {
		return false, err
	}
	return hmac.Equal(hash.Sum(nil), signature), nil
}
