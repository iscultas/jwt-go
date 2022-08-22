package jwa

import (
	"crypto"
	"crypto/rsa"
)

type rsassaPKCS1V15 struct {
	signingAlgorithm
}

var (
	rs256 = &rsassaPKCS1V15{signingAlgorithm{"RS256", crypto.SHA256}}
	rs384 = &rsassaPKCS1V15{signingAlgorithm{"RS384", crypto.SHA384}}
	rs512 = &rsassaPKCS1V15{signingAlgorithm{"RS512", crypto.SHA512}}
)

func RS256() *rsassaPKCS1V15 { return rs256 }

func RS384() *rsassaPKCS1V15 { return rs384 }

func RS512() *rsassaPKCS1V15 { return rs512 }

func (algorithm *rsassaPKCS1V15) Sign(token []byte, key any) ([]byte, error) {
	hash := algorithm.hash.New()

	if _, err := hash.Write(token); err != nil {
		return nil, err
	}

	return rsa.SignPKCS1v15(nil, key.(*rsa.PrivateKey), algorithm.hash, hash.Sum(nil))
}

func (algorithm *rsassaPKCS1V15) Verify(unsignedToken, signature []byte, key any) (bool, error) {
	hash := algorithm.hash.New()
	if _, err := hash.Write(unsignedToken); err != nil {
		return false, err
	}

	err := rsa.VerifyPKCS1v15(key.(*rsa.PublicKey), algorithm.hash, hash.Sum(nil), signature)
	return err == nil, err
}
