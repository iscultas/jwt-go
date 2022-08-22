package jws

import (
	"encoding/base64"
	"encoding/json"

	"github.com/iscultas/jwt-go/header"
)

type Signature struct {
	ProtectedHeader *header.Header
	Header          *header.Header
	Signature       []byte
}

func WithProtectedHeader(options ...func(*header.Header)) func(*Signature) {
	return func(signature *Signature) {
		for _, option := range options {
			option(signature.ProtectedHeader)
		}
	}
}

func WithHeader(options ...func(*header.Header)) func(*Signature) {
	return func(signature *Signature) {
		signature.Header = new(header.Header)

		for _, option := range options {
			option(signature.Header)
		}
	}
}

func UnmarshalSignature(rawHeader, signature string) (*Signature, error) {
	decodedHeader, err := header.DecodeHeader(rawHeader)
	if err != nil {
		return nil, err
	}

	signature_, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return nil, err
	}

	return &Signature{decodedHeader, nil, signature_}, nil
}

func (signature *Signature) String() string {
	return base64.RawURLEncoding.EncodeToString(signature.Signature)
}

type rawSignature struct {
	ProtectedHeader string         `json:"protected"`
	Header          *header.Header `json:"header"`
	Signature       string         `json:"signature"`
}

func (signature *Signature) MarshalJSON() ([]byte, error) {
	return json.Marshal(
		&rawSignature{
			ProtectedHeader: signature.ProtectedHeader.String(),
			Header:          signature.Header,
			Signature:       signature.String(),
		},
	)
}

func (signature *Signature) UnmarshalJSON(data []byte) error {
	var rawSignature rawSignature

	if err := json.Unmarshal(data, &rawSignature); err != nil {
		return err
	}

	if protectedHeader, err := header.DecodeHeader(rawSignature.ProtectedHeader); err == nil {
		signature.ProtectedHeader = protectedHeader
	} else {
		return err
	}

	signature.Header = rawSignature.Header

	decodedSignature, err := base64.RawURLEncoding.DecodeString(rawSignature.Signature)
	if err == nil {
		signature.Signature = decodedSignature
	}

	return err
}
