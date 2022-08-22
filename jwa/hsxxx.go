package jwa

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
)

func HS256(secret []byte) Signature {
	return &signature{"HS256", hmac.New(sha256.New, secret)}
}

func HS384(secret []byte) Signature {
	return &signature{"HS384", hmac.New(sha512.New384, secret)}
}

func HS512(secret []byte) Signature {
	return &signature{"HS512", hmac.New(sha512.New, secret)}
}
