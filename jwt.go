package jwt

import (
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/iscultas/jwt-go/jwa"
)

type Jwt struct {
	claims    map[string]any
	signature jwa.Signature
}

func NewJwt() *Jwt {
	return &Jwt{map[string]any{}, nil}
}

func (jwt *Jwt) SetIssuer(issuer string) *Jwt {
	jwt.claims["iss"] = issuer

	return jwt
}

func (jwt *Jwt) SetSubject(subject string) *Jwt {
	jwt.claims["sub"] = subject

	return jwt
}

func (jwt *Jwt) SetAudience(audience string) *Jwt {
	jwt.claims["aud"] = audience

	return jwt
}

func (jwt *Jwt) SetExpirationTime(expirationTime time.Time) *Jwt {
	jwt.claims["exp"] = expirationTime.Unix()

	return jwt
}

func (jwt *Jwt) SetNotBefore(notBefore time.Time) *Jwt {
	jwt.claims["nbf"] = notBefore.Unix()

	return jwt
}

func (jwt *Jwt) SetIssuedAt(issuedAt time.Time) *Jwt {
	jwt.claims["iat"] = issuedAt.Unix()

	return jwt
}

func (jwt *Jwt) SetJwtId(jwtId string) *Jwt {
	jwt.claims["jti"] = jwtId

	return jwt
}

func (jwt *Jwt) Sign(signature jwa.Signature) *Jwt {
	jwt.signature = signature

	return jwt
}

func (jwt *Jwt) String() string {
	signature := jwt.signature
	if signature == nil {
		signature = jwa.None()
	}

	headerJson, err := json.Marshal(signature.Header())
	if err != nil {
		panic(err)
	}

	payload, err := json.Marshal(jwt.claims)
	if err != nil {
		panic(err)
	}

	signingInput := base64.RawURLEncoding.EncodeToString(headerJson) + "." + base64.RawURLEncoding.EncodeToString(payload)

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature.Sign([]byte(signingInput)))
}

func (jwt *Jwt) MarshalJSON() ([]byte, error) {
	payload, err := json.Marshal(jwt.claims)
	if err != nil {
		return nil, err
	}

	jwt_ := struct {
		Payload   string `json:"payload"`
		Signature string `jsno:"signature"`
	}{
		Payload: base64.RawURLEncoding.EncodeToString(payload),
	}
	return json.Marshal(jwt_)
}

func Decode(jwt string) (*Jwt, error) {
	return nil, nil
}
