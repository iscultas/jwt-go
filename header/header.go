package header

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"slices"

	"github.com/iscultas/jwt-go/jwa"
	"github.com/iscultas/jwt-go/jwk"
)

type Header struct {
	Type                            string
	ContentType                     string
	Algorithm                       jwa.Algorithm
	JWKSetURL                       *url.URL
	JWK                             *jwk.Key
	KeyID                           string
	X509URL                         *url.URL
	X509CertificateChain            string
	X509CertificateSHA1Thumbprint   string
	X509CertificateSHA256Thumbprint string
	Critical                        []string
	EncryptionAlgorithm             string
	CompressionAlgorithm            string
	RawHeader                       string
}

func WithJWKSetURL(url *url.URL) func(*Header) {
	return func(header *Header) { header.JWKSetURL = url }
}

func WithJWK(jwk *jwk.Key) func(*Header) {
	return func(header *Header) { header.JWK = jwk }
}

func WithKeyID(id string) func(*Header) {
	return func(header *Header) { header.KeyID = id }
}

func WithX509Url(url *url.URL) func(*Header) {
	return func(header *Header) { header.X509URL = url }
}

func WithX509CertificateChain(chain string) func(*Header) {
	return func(header *Header) { header.X509CertificateChain = chain }
}

func WithX509CertificateSha1Thumbprint(thumbprint string) func(*Header) {
	return func(header *Header) { header.X509CertificateSHA1Thumbprint = thumbprint }
}

func WithX509CertificateSha256Thumbprint(thumbprint string) func(*Header) {
	return func(header *Header) { header.X509CertificateSHA256Thumbprint = thumbprint }
}

func WithCritical(parameters ...string) func(*Header) {
	return func(header *Header) { header.Critical = parameters }
}

type rawHeader struct {
	Type                            string   `json:"typ,omitempty"`
	ContentType                     string   `json:"cty,omitempty"`
	Algorithm                       string   `json:"alg,omitempty"`
	JWKSetURL                       string   `json:"jku,omitempty"`
	JWK                             *jwk.Key `json:"jwk,omitempty"`
	KeyID                           string   `json:"kid,omitempty"`
	X509URL                         string   `json:"x5u,omitempty"`
	X509CertificateChain            string   `json:"x5c,omitempty"`
	X509CertificateSHA1Thumbprint   string   `json:"x5t,omitempty"`
	X509CertificateSHA256Thumbprint string   `json:"x5t#S256,omitempty"`
	Critical                        []string `json:"crit,omitempty"`
	EncryptionAlgorithm             string   `json:"enc,omitempty"`
	CompressionAlgorithm            string   `json:"zip,omitempty"`
}

func (header *Header) MarshalJSON() ([]byte, error) {
	rawHeader := &rawHeader{
		Type:                            header.Type,
		ContentType:                     header.ContentType,
		JWK:                             header.JWK,
		KeyID:                           header.KeyID,
		X509CertificateChain:            header.X509CertificateChain,
		X509CertificateSHA1Thumbprint:   header.X509CertificateSHA1Thumbprint,
		X509CertificateSHA256Thumbprint: header.X509CertificateSHA256Thumbprint,
	}

	if header.Algorithm != nil {
		rawHeader.Algorithm = header.Algorithm.String()
	}

	if header.JWKSetURL != nil {
		rawHeader.JWKSetURL = header.JWKSetURL.String()
	}

	if header.X509URL != nil {
		rawHeader.X509URL = header.X509URL.String()
	}

	return json.Marshal(rawHeader)
}

var algorithms = []jwa.Algorithm{
	jwa.None(),
	jwa.HS256(), jwa.HS384(), jwa.HS512(),
	jwa.RS256(), jwa.RS384(), jwa.RS512(),
	jwa.ES256(), jwa.ES384(), jwa.ES512(),
	jwa.PS256(), jwa.PS384(), jwa.PS512(),
}

func (header *Header) UnmarshalJSON(data []byte) error {
	rawHeader := new(rawHeader)

	if err := json.Unmarshal(data, rawHeader); err != nil {
		return err
	}

	i := slices.IndexFunc[[]jwa.Algorithm](algorithms, func(algorithm jwa.Algorithm) bool { return algorithm.String() == rawHeader.Algorithm })
	if i == -1 {
		// TODO: add proper error type
		return errors.New("unsupported algorithm")
	}

	header.Type = rawHeader.Type
	header.ContentType = rawHeader.ContentType
	header.Algorithm = algorithms[i]

	if jwkSetURL, err := url.Parse(rawHeader.JWKSetURL); err == nil {
		header.JWKSetURL = jwkSetURL
	}

	header.JWK = rawHeader.JWK
	header.KeyID = rawHeader.KeyID

	if x509URL, err := url.Parse(rawHeader.X509URL); err == nil {
		header.X509URL = x509URL
	}

	header.X509CertificateChain = rawHeader.X509CertificateChain
	header.X509CertificateSHA1Thumbprint = rawHeader.X509CertificateSHA1Thumbprint
	header.X509CertificateSHA256Thumbprint = rawHeader.X509CertificateSHA256Thumbprint
	header.Critical = rawHeader.Critical

	return nil
}

func DecodeHeader(header string) (*Header, error) {
	headerJson, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		return nil, err
	}

	decodedHeader := new(Header)
	if err := json.Unmarshal(headerJson, &decodedHeader); err != nil {
		return nil, err
	}

	decodedHeader.RawHeader = header

	return decodedHeader, nil
}

func (header *Header) String() string {
	if header.RawHeader != "" {
		return header.RawHeader
	}

	headerJson, err := json.Marshal(header)
	if err != nil {
		panic(err)
	}

	return base64.RawURLEncoding.EncodeToString(headerJson)
}
