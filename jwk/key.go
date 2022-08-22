package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/url"
	"slices"

	"github.com/iscultas/jwt-go/jwa"
)

type Type string

const (
	EllipticCurve Type = "EC"
	RSA           Type = "RSA"
	OctetSequence Type = "oct"
)

type PublicKeyUse string

const (
	Signature  PublicKeyUse = "sig"
	Encryption PublicKeyUse = "enc"
)

type Operation string

const (
	Sign       Operation = "sign"
	Verify     Operation = "verify"
	Encrypt    Operation = "encrypt"
	Decrypt    Operation = "decrypt"
	WrapKey    Operation = "wrapKey"
	UnwrapKey  Operation = "unwrapKey"
	DeriveKey  Operation = "deriveKey"
	DeriveBits Operation = "deriveBits"
)

type Key struct {
	typee        Type
	publicKeyUse PublicKeyUse
	operations   []Operation
	algorithm    jwa.Algorithm
	id           string

	x509URL                         *url.URL
	x509CertificateChain            []*x509.Certificate
	x509CertificateSHA1Thumbprint   string
	x509CertificateSHA256Thumbprint string

	material any
}

var ErrUnsupportedKeyType = errors.New("unsupported key type")

func NewKey(material any, options ...func(*Key)) *Key {
	var typee Type

	switch material.(type) {
	case *ecdsa.PublicKey, *ecdsa.PrivateKey:
		typee = EllipticCurve
	case *rsa.PublicKey, *rsa.PrivateKey:
		typee = RSA
	case []byte:
		typee = OctetSequence
	}

	key := &Key{
		typee:    typee,
		material: material,
	}

	for _, option := range options {
		option(key)
	}

	return key
}

func (key *Key) Material() any {
	return key.material
}

func WithPublicKeyUse(publicKeyUse PublicKeyUse) func(*Key) {
	return func(key *Key) {
		key.publicKeyUse = publicKeyUse
	}
}

func WithOperations(operations ...Operation) func(*Key) {
	return func(key *Key) {
		key.operations = operations
	}
}

func WithAlgorithm(algorithm jwa.Algorithm) func(*Key) {
	return func(key *Key) {
		key.algorithm = algorithm
	}
}

func WithId(id string) func(*Key) {
	return func(key *Key) {
		key.id = id
	}
}

func WithX509Url(url *url.URL) func(*Key) {
	return func(key *Key) { key.x509URL = url }
}

func WithX509CertificateChain(chain []*x509.Certificate) func(*Key) {
	return func(key *Key) { key.x509CertificateChain = chain }
}

func WithX509CertificateSHA1Thumbprint(thumbprint string) func(*Key) {
	return func(key *Key) { key.x509CertificateSHA1Thumbprint = thumbprint }
}

func WithX509CertificateSHA256Thumbprint(thumbprint string) func(*Key) {
	return func(key *Key) { key.x509CertificateSHA256Thumbprint = thumbprint }
}

func (key *Key) weight(publicKeyUse PublicKeyUse, operations []Operation, algorithm jwa.Algorithm, id string) uint8 {
	var weight uint8 = 0

	if key.publicKeyUse == publicKeyUse {
		weight += 16
	}

	for _, operation := range operations {
		if slices.Contains[[]Operation](key.operations, operation) {
			weight += 8
		}
	}

	if key.algorithm == algorithm {
		weight += 64
	}

	if key.id == id {
		weight += 128
	}

	return weight
}

type rawKey struct {
	Type         Type         `json:"kty,omitempty"`
	PublicKeyUse PublicKeyUse `json:"use,omitempty"`
	Operations   []Operation  `json:"key_ops,omitempty"`
	Algorithm    string       `json:"alg,omitempty"`
	Id           string       `json:"kid,omitempty"`

	X509Url                         string   `json:"x5u,omitempty"`
	X509CertificateChain            []string `json:"x5c,omitempty"`
	X509CertificateSha1Thumbprint   string   `json:"x5t,omitempty"`
	X509CertificateSha256Thumbprint string   `json:"x5t#S256,omitempty"`

	Curve string `json:"crv,omitempty"`
	X     string `json:"x,omitempty"`
	Y     string `json:"y,omitempty"`

	D string `json:"d,omitempty"`

	N   string   `json:"n,omitempty"`
	E   string   `json:"e,omitempty"`
	P   string   `json:"p,omitempty"`
	Q   string   `json:"q,omitempty"`
	Dp  string   `json:"dp,omitempty"`
	Dq  string   `json:"dq,omitempty"`
	Qi  string   `json:"qi,omitempty"`
	Oth []string `json:"oth,omitempty"`

	K string `json:"k,omitempty"`
}

func bigIntToBase64(integer *big.Int) string {
	if integer == nil {
		return ""
	}

	return base64.RawURLEncoding.EncodeToString(integer.Bytes())
}

func (key *Key) MarshalJSON() ([]byte, error) {
	rawKey := &rawKey{
		Type:         key.typee,
		PublicKeyUse: key.publicKeyUse,
		Operations:   key.operations,
		Id:           key.id,

		X509CertificateSha1Thumbprint:   key.x509CertificateSHA1Thumbprint,
		X509CertificateSha256Thumbprint: key.x509CertificateSHA256Thumbprint,
	}

	if key.algorithm != nil {
		rawKey.Algorithm = key.algorithm.String()
	}

	if key.x509URL != nil {
		rawKey.X509Url = key.x509URL.String()
	}

	for _, certificate := range key.x509CertificateChain {
		rawKey.X509CertificateChain = append(rawKey.X509CertificateChain, base64.StdEncoding.EncodeToString(certificate.Raw))
	}

	switch key := key.material.(type) {
	case *ecdsa.PublicKey:
		rawKey.Curve = key.Curve.Params().Name
		rawKey.X = bigIntToBase64(key.X)
		rawKey.Y = bigIntToBase64(key.Y)
	case *ecdsa.PrivateKey:
		rawKey.Curve = key.Curve.Params().Name
		rawKey.X = bigIntToBase64(key.X)
		rawKey.Y = bigIntToBase64(key.Y)

		rawKey.D = bigIntToBase64(key.D)
	case *rsa.PublicKey:
		rawKey.N = bigIntToBase64(key.N)
		rawKey.E = bigIntToBase64(big.NewInt(int64(key.E)))
	case *rsa.PrivateKey:
		rawKey.N = bigIntToBase64(key.N)
		rawKey.E = bigIntToBase64(big.NewInt(int64(key.E)))

		rawKey.D = bigIntToBase64(key.D)

		rawKey.P = bigIntToBase64(key.Primes[0])
		rawKey.Q = bigIntToBase64(key.Primes[1])

		rawKey.Dp = bigIntToBase64(key.Precomputed.Dp)
		rawKey.Dq = bigIntToBase64(key.Precomputed.Dq)
		rawKey.Qi = bigIntToBase64(key.Precomputed.Qinv)

		for _, prime := range key.Primes[2:] {
			rawKey.Oth = append(rawKey.Oth, bigIntToBase64(prime))
		}

	case []byte:
		rawKey.K = base64.RawURLEncoding.EncodeToString(key)
	}

	return json.Marshal(rawKey)
}

var algorithms = []jwa.Algorithm{
	jwa.None(),
	jwa.HS256(), jwa.HS384(), jwa.HS512(),
	jwa.RS256(), jwa.RS384(), jwa.RS512(),
	jwa.ES256(), jwa.ES384(), jwa.ES512(),
	jwa.PS256(), jwa.PS384(), jwa.PS512(),
}

func base64ToBigInt(s string) (*big.Int, error) {
	bytes, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}

	return new(big.Int).SetBytes(bytes), nil
}

var curves = []elliptic.Curve{
	elliptic.P256(),
	elliptic.P384(),
	elliptic.P521(),
}

type MissingRequiredParameterError struct {
	parameter string
}

func (error MissingRequiredParameterError) Error() string {
	return "jwk: missing required parameter: " + error.parameter
}

func (key *Key) parseElipticCurve(rawKey *rawKey) error {
	if rawKey.Curve == "" {
		return &MissingRequiredParameterError{"crv"}
	}

	curveIndex := slices.IndexFunc[[]elliptic.Curve](curves, func(curve elliptic.Curve) bool { return curve.Params().Name == rawKey.Curve })
	if curveIndex == -1 {
		return nil
	}

	if rawKey.X == "" {
		return &MissingRequiredParameterError{"x"}
	}
	x, err := base64ToBigInt(rawKey.X)
	if err != nil {
		return err
	}

	if rawKey.Y == "" {
		return &MissingRequiredParameterError{"y"}
	}
	y, err := base64ToBigInt(rawKey.Y)
	if err != nil {
		return err
	}

	publicKey := ecdsa.PublicKey{
		Curve: curves[curveIndex],
		X:     x,
		Y:     y,
	}

	if rawKey.D == "" {
		key.material = &publicKey
	} else {
		d, err := base64ToBigInt(rawKey.D)
		if err != nil {
			return err
		}

		key.material = &ecdsa.PrivateKey{
			PublicKey: publicKey,
			D:         d,
		}
	}

	return nil
}

func parseRSAPrivateKey(rawKey *rawKey, publicKey rsa.PublicKey) (*rsa.PrivateKey, error) {
	d, err := base64ToBigInt(rawKey.D)
	if err != nil {
		return nil, err
	}

	rawPrimes := append([]string{rawKey.P, rawKey.Q}, rawKey.Oth...)

	var primes []*big.Int
	for _, rawPrime := range rawPrimes {
		if prime, err := base64ToBigInt(rawPrime); err == nil {
			primes = append(primes, prime)
		} else {
			return nil, err
		}
	}

	dp, err := base64ToBigInt(rawKey.Dp)
	if err != nil {
		return nil, err
	}

	dq, err := base64ToBigInt(rawKey.Dq)
	if err != nil {
		return nil, err
	}

	qi, err := base64ToBigInt(rawKey.Qi)
	if err != nil {
		return nil, err
	}

	privateKey := &rsa.PrivateKey{
		PublicKey: publicKey,
		D:         d,
		Primes:    primes,
		Precomputed: rsa.PrecomputedValues{
			Dp:        dp,
			Dq:        dq,
			Qinv:      qi,
			CRTValues: []rsa.CRTValue{},
		},
	}
	privateKey.Precompute()

	return privateKey, nil
}

func (key *Key) parseRSA(rawKey *rawKey) error {
	n, err := base64ToBigInt(rawKey.N)
	if err != nil {
		return err
	}

	e, err := base64ToBigInt(rawKey.E)
	if err != nil {
		return err
	}

	publicKey := rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}

	if rawKey.D != "" && rawKey.P != "" && rawKey.Q != "" {
		privateKey, err := parseRSAPrivateKey(rawKey, publicKey)
		if err != nil {
			return err
		}

		key.material = privateKey
	} else {
		key.material = publicKey
	}

	return nil
}

func (key *Key) parseOctetSequence(rawKey *rawKey) error {
	if rawKey.K == "" {
		return &MissingRequiredParameterError{"k"}
	}

	material, err := base64.RawURLEncoding.DecodeString(rawKey.K)
	if err == nil {
		key.material = material
	}

	return err
}

func (key *Key) UnmarshalJSON(data []byte) error {
	rawKey := new(rawKey)

	var err error

	if err = json.Unmarshal(data, rawKey); err != nil {
		return err
	}

	key.typee = rawKey.Type
	key.publicKeyUse = rawKey.PublicKeyUse
	key.operations = rawKey.Operations

	if rawKey.Algorithm != "" {
		index := slices.IndexFunc[[]jwa.Algorithm](algorithms, func(algorithm jwa.Algorithm) bool { return algorithm.String() == rawKey.Algorithm })
		if index == -1 {
			// TODO: add proper error type
			return errors.New("unsupported algorithm")
		} else {
			key.algorithm = algorithms[index]
		}
	}

	key.id = rawKey.Id

	if rawKey.X509Url != "" {
		if x509URL, err := url.Parse(rawKey.X509Url); err == nil {
			key.x509URL = x509URL
		} else {
			return err
		}
	}

	for _, base64EncodedCertificate := range rawKey.X509CertificateChain {
		derEncodedCertificate, err := base64.StdEncoding.DecodeString(base64EncodedCertificate)
		if err != nil {
			return err
		}

		certificate, err := x509.ParseCertificate(derEncodedCertificate)
		if err != nil {
			return err
		}

		key.x509CertificateChain = append(key.x509CertificateChain, certificate)
	}

	key.x509CertificateSHA1Thumbprint = rawKey.X509CertificateSha1Thumbprint
	key.x509CertificateSHA256Thumbprint = rawKey.X509CertificateSha256Thumbprint

	switch rawKey.Type {
	case EllipticCurve:
		return key.parseElipticCurve(rawKey)
	case RSA:
		return key.parseRSA(rawKey)
	case OctetSequence:
		return key.parseOctetSequence(rawKey)
	}

	return err
}

type KeySet struct {
	Keys []*Key `json:"keys"`
}

func NewKeySet(keys ...*Key) *KeySet {
	return &KeySet{Keys: keys}
}

func (keySet *KeySet) Key(publicKeyUse PublicKeyUse, operations []Operation, algorithm jwa.Algorithm, id string) *Key {
	selectedKey := keySet.Keys[0]

	for _, key := range keySet.Keys {
		if key.weight(publicKeyUse, operations, algorithm, id) > selectedKey.weight(publicKeyUse, operations, algorithm, id) {
			selectedKey = key
		}
	}

	return selectedKey
}
