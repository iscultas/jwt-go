package jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/iscultas/jwt-go/header"
	"github.com/iscultas/jwt-go/jwa"
	"github.com/iscultas/jwt-go/jwk"
	"github.com/iscultas/jwt-go/jws"
)

type payload struct {
	claims     map[string]any
	rawPayload string
}

func (payload *payload) Set(key string, value any) {
	payload.claims[key] = value
}

func (payload *payload) Get(key string) any {
	return payload.claims[key]
}

func (payload *payload) String() string {
	if payload.rawPayload == "" {
		payloadJson, err := json.Marshal(payload.claims)
		if err != nil {
			panic(err)
		}

		payload.rawPayload = base64.RawURLEncoding.EncodeToString(payloadJson)
	}

	return payload.rawPayload
}

func unmarshalPayload(rawPayload string) (*payload, error) {
	payloadJson, err := base64.RawURLEncoding.DecodeString(rawPayload)
	if err != nil {
		return nil, err
	}

	claims := make(map[string]any)
	if err := json.Unmarshal(payloadJson, &claims); err != nil {
		return nil, err
	}

	return &payload{claims, rawPayload}, nil
}

type Token struct {
	payload    *payload
	signatures []*jws.Signature
}

func NewToken(options ...func(*Token) error) (*Token, error) {
	token := &Token{&payload{make(map[string]any), ""}, make([]*jws.Signature, 0)}

	for _, option := range options {
		if err := option(token); err != nil {
			return nil, err
		}
	}

	return token, nil
}

func WithIssuer(issuer string) func(*Token) error {
	return func(token *Token) error {
		token.payload.Set("iss", issuer)

		return nil
	}
}

func (token *Token) Issuer() string { return token.payload.Get("iss").(string) }

func WithSubject(subject string) func(*Token) error {
	return func(token *Token) error {
		token.payload.Set("sub", subject)

		return nil
	}
}

func (token *Token) Subject() string { return token.payload.Get("sub").(string) }

func WithAudience(audience string) func(*Token) error {
	return func(token *Token) error {
		token.payload.Set("aud", audience)

		return nil
	}
}

func (token *Token) Audience() string { return token.payload.Get("aud").(string) }

func WithExpirationTime(expirationTime time.Time) func(*Token) error {
	return func(token *Token) error {
		token.payload.Set("exp", float64(expirationTime.Unix()))

		return nil
	}
}

func (token *Token) ExpirationTime() time.Time {
	if rawExpirationTime := token.payload.Get("exp"); rawExpirationTime == nil {
		return time.Unix(math.MaxInt32, 0)
	} else {
		return time.Unix(int64(rawExpirationTime.(float64)), 0)
	}
}

func WithNotBefore(notBefore time.Time) func(*Token) error {
	return func(token *Token) error {
		token.payload.Set("nbf", float64(notBefore.Unix()))

		return nil
	}
}

func (token *Token) NotBefore() time.Time {
	if rawNotBefore := token.payload.Get("nbf"); rawNotBefore == nil {
		return time.Unix(math.MinInt32, 0)
	} else {
		return time.Unix(int64(rawNotBefore.(float64)), 0)
	}
}

func WithIssuedAt(issuedAt *time.Time) func(*Token) error {
	return func(token *Token) error {
		token.payload.Set("iat", float64(issuedAt.Unix()))

		return nil
	}
}

func (token *Token) IssuedAt() time.Time {
	if rawIssuedAt := token.payload.Get("iat"); rawIssuedAt == nil {
		return time.Unix(math.MaxInt32, 0)
	} else {
		return time.Unix(int64(rawIssuedAt.(float64)), 0)
	}
}

func WithId(id string) func(*Token) error {
	return func(token *Token) error {
		token.payload.Set("jti", id)

		return nil
	}
}

func (token *Token) Id() string { return token.payload.Get("jti").(string) }

func WithPrivateClaim(key string, value any) func(*Token) error {
	return func(token *Token) error {
		token.payload.Set(key, value)

		return nil
	}
}

func (token *Token) PrivateClaim(key string) any {
	return token.payload.Get(key)
}

func WithSignature(algorithm jwa.Signer, key *jwk.Key, options ...func(*jws.Signature)) func(*Token) error {
	return func(token *Token) error {
		header := &header.Header{Type: "JWT", Algorithm: algorithm}

		var unsignedToken bytes.Buffer
		unsignedToken.WriteString(header.String())
		unsignedToken.WriteRune('.')
		unsignedToken.WriteString(token.payload.String())

		var keyMaterial any = nil
		if key != nil {
			keyMaterial = key.Material()
		}

		rawSignature, err := algorithm.Sign(unsignedToken.Bytes(), keyMaterial)
		if err == nil {
			signature := &jws.Signature{ProtectedHeader: header, Signature: rawSignature}

			for _, option := range options {
				option(signature)
			}

			token.signatures = append(token.signatures, signature)
		}
		return err
	}
}

type verificationConfig struct {
	algorithms []jwa.Algorithm
}

var DefaultVerificationConfig = verificationConfig{
	algorithms: []jwa.Algorithm{
		jwa.HS256(), jwa.HS384(), jwa.HS512(),
		jwa.RS256(), jwa.RS384(), jwa.RS512(),
		jwa.ES256(), jwa.ES384(), jwa.ES512(),
		jwa.PS256(), jwa.PS384(), jwa.PS512(),
	},
}

func (token *Token) Verify(keySet *jwk.KeySet, config verificationConfig) error {
	now := time.Now()

	if now.After(token.ExpirationTime()) {
		// TODO: add proper error type
		return errors.New("expired")
	}

	if now.Before(token.NotBefore()) {
		// TODO: add proper error type
		return errors.New("not valid yet")
	}

	var unsignedToken bytes.Buffer

	for _, signature := range token.signatures {
		i := slices.IndexFunc[[]jwa.Algorithm](config.algorithms, func(algorithm jwa.Algorithm) bool { return algorithm == signature.ProtectedHeader.Algorithm })
		if i == -1 {
			// TODO: add proper error type
			return errors.New("forbidden algorithm")
		}

		algorithm := config.algorithms[i].(jwa.Verifier)

		unsignedToken.WriteString(signature.ProtectedHeader.String())
		unsignedToken.WriteRune('.')
		unsignedToken.WriteString(token.payload.String())

		key := keySet.Key(jwk.Signature, []jwk.Operation{jwk.Verify}, algorithm, signature.ProtectedHeader.KeyID)

		if verified, err := algorithm.Verify(unsignedToken.Bytes(), signature.Signature, key.Material()); !verified || err != nil {
			// TODO: add proper error type
			return errors.New("unverified")
		}

		unsignedToken.Reset()
	}

	return nil
}

func (token *Token) String() string {
	signature := token.signatures[0]

	var builder strings.Builder
	builder.WriteString(signature.ProtectedHeader.String())
	builder.WriteRune('.')
	builder.WriteString(token.payload.String())
	builder.WriteRune('.')
	builder.WriteString(signature.String())
	return builder.String()
}

func Unmarshal(token string) (*Token, error) {
	parts := strings.Split(token, ".")

	signature, err := jws.UnmarshalSignature(parts[0], parts[2])
	if err != nil {
		return nil, err
	}

	payload, err := unmarshalPayload(parts[1])
	if err != nil {
		return nil, err
	}

	return &Token{payload, []*jws.Signature{signature}}, nil
}

type rawToken struct {
	Payload         string           `json:"payload"`
	Signatures      []*jws.Signature `json:"signatures,omitempty"`
	ProtectedHeader string           `json:"protected,omitempty"`
	Header          *header.Header   `json:"header,omitempty"`
	Signature       string           `json:"signature,omitempty"`
}

func (token *Token) MarshalJSON() ([]byte, error) {
	rawToken := rawToken{Payload: token.payload.String()}

	switch len(token.signatures) {
	case 0:

	case 1:
		signature := token.signatures[0]

		rawToken.ProtectedHeader = signature.ProtectedHeader.String()
		rawToken.Header = signature.Header
		rawToken.Signature = signature.String()
	default:
		rawToken.Signatures = token.signatures
	}

	return json.Marshal(&rawToken)
}

func (token *Token) UnmarshalJSON(data []byte) error {
	rawToken := new(rawToken)

	if err := json.Unmarshal(data, rawToken); err != nil {
		return err
	}

	if rawToken.Payload == "" {
		// TODO: add proper error type
		return errors.New("missing payload")
	}

	payload, err := unmarshalPayload(rawToken.Payload)
	if err != nil {
		return err
	}

	token.payload = payload

	var signatures []*jws.Signature

	if (rawToken.ProtectedHeader != "" || rawToken.Header != nil) && rawToken.Signature != "" {
		decodedSignature, err := jws.UnmarshalSignature(rawToken.ProtectedHeader, rawToken.Signature)
		if err != nil {
			return err
		}

		decodedSignature.Header = rawToken.Header

		signatures = append(signatures, decodedSignature)
	} else {
		signatures = rawToken.Signatures
	}

	token.signatures = signatures

	return nil
}
