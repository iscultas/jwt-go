package jwa

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"math"
	"math/big"
)

type ecdsa_ struct {
	signingAlgorithm
}

var (
	es256 = &ecdsa_{signingAlgorithm{"ES256", crypto.SHA256}}
	es384 = &ecdsa_{signingAlgorithm{"ES384", crypto.SHA384}}
	es512 = &ecdsa_{signingAlgorithm{"ES512", crypto.SHA512}}
)

func ES256() *ecdsa_ { return es256 }

func ES384() *ecdsa_ { return es384 }

func ES512() *ecdsa_ { return es512 }

func (algorithm *ecdsa_) Sign(token []byte, key any) ([]byte, error) {
	hash := algorithm.hash.New()

	if _, err := hash.Write(token); err != nil {
		return nil, err
	}

	privateKey := key.(*ecdsa.PrivateKey)

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash.Sum(nil))
	if err != nil {
		return nil, err
	}

	signatureLength := int(math.Ceil(float64(privateKey.Params().BitSize)/8)) * 2

	signature := make([]byte, signatureLength)
	copy(signature[signatureLength/2-len(r.Bytes()):signatureLength/2], r.Bytes())
	copy(signature[signatureLength-len(s.Bytes()):], s.Bytes())

	return signature, nil
}

func (algorithm *ecdsa_) Verify(unsignedToken, signature []byte, key any) (bool, error) {
	hash := algorithm.hash.New()
	if _, err := hash.Write(unsignedToken); err != nil {
		return false, err
	}

	r := new(big.Int).SetBytes(signature[:len(signature)/2])
	s := new(big.Int).SetBytes(signature[len(signature)/2:])

	return ecdsa.Verify(key.(*ecdsa.PublicKey), hash.Sum(nil), r, s), nil
}
