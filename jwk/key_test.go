package jwk_test

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"

	"github.com/iscultas/jwt-go/jwk"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("JWK", func() {
	var key *jwk.Key
	var encodedKey string

	Context("RSA", func() {
		BeforeEach(func() {
			block, _ := pem.Decode(
				[]byte(`
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78L
hWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc/BJECPebWKRXjBZCiFV4n3oknj
hMstn64tZ/2W+5JsGY4Hc5n9yBXArwl93lqt7/RN5w6Cf0h4QyQ5v+65YGjQR0/F
DW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbO
pbISD08qNLyrdkt+bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ+G/xBni
Iqbw0Ls1jF44+csFCur+kEgU8awapJzKnqDKgwIDAQABAoIBAF+HE7XiWP4J+BWD
7FwfK3V4seb8LINRSzeRNxGhukSaFR/hyyyg/TO3ceaKOxlEZJ3IZ60cHlJAu4U+
XySzNFmxQCjS1mNr7+wejal0s1L8U9P2En6oo8Kd0U85QWgsVqeHaBZOTdqPBsv5
xzSq6AAyJCeOqUVKIbF8sG0XgHWGjMBbPbb/Hf3D1WN4tO2t7fDDekzcJtHUmsJv
b+O1Igpd0pOWYhu8aIzy7uLG4NVNo8eCAUzQc52yUsxRyuuo0/G4JLqrJNBo7JAy
ZNfWeKsI8G7J5+I9lgYot0S/lLNpRlZGPH5Bc5ntc9B2yJH89GOpqpzmLanNF+I3
3CqAAvECgYEA83i+7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxt
PVnwD20R+60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQy
qVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfsCgYEA3dfO
R9cuYq+0S+mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgT
nCdpYzBcOfW5r370AFXjiWft/NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ+1k
Yd/s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxkCgYAbiw9eRzphr3Lyglb38guP
jG6mm7SXOL8ftVORLzGPlJ1fdygTSiKZjDEiLZ6ZMC57RQ5rl2mAUbIEnhzy1DZU
XjTZdG6AoNM/xqRiEWjm0ADvtB782a25hlzcLebcjbgbYa9HmxIPFTIA3bOrwt+f
0RSazqtjc5vxh6IqROIGPQKBgQCz2UAf1+CAGygVHw5pzZH8TaDDbzatPaQY4CG8
iWURMTV5+sDqG5RS8x8FwymfyWp5bq/POdhjlJJAXukx0L9qAjecbwhunUFRvQlS
KtpE2pR8uFxBv930YXgOHt7vhZtGyhtGie6NNg3XEJo/pM7rWO9atf4vXy3FfDj3
hD9yCQKBgBsjP6eia18kos9baBYCm1lfiXSN40OMqbva2zFsd60CQX5rdBaGM4FC
GRFRRHDqsHpkTfNc6AwGmvgZNCljRg4yR2Q3Q5hYVtwDe5SPqbsZP5h2Ridda8ck
fDueVy0nt0j5kXysGSOslNuGcb0ChWCLXZXVChszuiGus0yoQFUV
-----END RSA PRIVATE KEY-----
`),
			)

			rsaPrivateKey, _ := x509.ParsePKCS1PrivateKey(block.Bytes)

			key = jwk.NewKey(rsaPrivateKey)

			encodedKey = "{\"kty\":\"RSA\",\"d\":\"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\",\"e\":\"AQAB\",\"p\":\"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs\",\"q\":\"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk\",\"dp\":\"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0\",\"dq\":\"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk\",\"qi\":\"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU\"}"

		})

		It("Encoding", func() {
			encodedKey_, err := json.Marshal(key)
			Expect(err).To(BeNil())
			Expect(encodedKey_).To(Equal([]byte(encodedKey)))
		})

		It("Decoding", func() {
			key_ := new(jwk.Key)
			err := json.Unmarshal([]byte(encodedKey), key_)
			Expect(err).To(BeNil())
			Expect(key_).To(Equal(key))
		})
	})

	Context("Symmetric", func() {
		BeforeEach(func() {
			symmetricKey, _ := base64.RawURLEncoding.DecodeString("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow")

			key = jwk.NewKey(symmetricKey)

			encodedKey = "{\"kty\":\"oct\",\"k\":\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow\"}"
		})

		It("Encoding", func() {
			encodedKey_, err := json.Marshal(key)
			Expect(err).To(BeNil())
			Expect(encodedKey_).To(Equal([]byte(encodedKey)))
		})

		It("Decoding", func() {
			key_ := new(jwk.Key)
			err := json.Unmarshal([]byte(encodedKey), key_)
			Expect(err).To(BeNil())
			Expect(key_).To(Equal(key))
		})
	})
})
