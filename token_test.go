package jwt_test

import (
	"encoding/base64"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/iscultas/jwt-go"
	"github.com/iscultas/jwt-go/jwa"
	"github.com/iscultas/jwt-go/jwk"
)

var _ = Describe("JWT", func() {
	const privateClaimKey = "http://example.com/is_root"

	expirationTime := time.Unix(2147483647, 0)

	var token *jwt.Token

	Describe("Encoding/decoding", func() {
		Context("Usign JWS Compact Serialization", func() {
			Context("Without signature or encryption", func() {
				BeforeEach(func() {
					token, _ = jwt.NewToken(
						jwt.WithIssuer("joe"),
						jwt.WithExpirationTime(expirationTime),
						jwt.WithPrivateClaim(privateClaimKey, true),
						jwt.WithSignature(jwa.None(), nil),
					)
				})

				It("can encode", func() {
					Expect(token.String()).To(Equal("eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJleHAiOjIxNDc0ODM2NDcsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlLCJpc3MiOiJqb2UifQ."))
				})

				It("can decode", func() {
					decodedToken, err := jwt.Unmarshal("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJleHAiOjIxNDc0ODM2NDcsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlLCJpc3MiOiJqb2UifQ.")

					Expect(err).To(BeNil())
					Expect(decodedToken.Issuer()).To(Equal(token.Issuer()))
					Expect(decodedToken.ExpirationTime()).To(Equal(token.ExpirationTime()))
					Expect(decodedToken.PrivateClaim(privateClaimKey)).To(Equal(token.PrivateClaim(privateClaimKey)))
				})
			})

			Context("With signature", func() {
				encodedToken := "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjIxNDc0ODM2NDcsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlLCJpc3MiOiJqb2UifQ.xqLr3bLT45gyQjFRTNO8WPgZ1i8UFGEhIc4-A-sJzbM"
				var key *jwk.Key

				BeforeEach(func() {
					symmetricKey, _ := base64.RawURLEncoding.DecodeString("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow")

					key = jwk.NewKey(symmetricKey)

					token, _ = jwt.NewToken(
						jwt.WithIssuer("joe"),
						jwt.WithExpirationTime(expirationTime),
						jwt.WithPrivateClaim(privateClaimKey, true),
						jwt.WithSignature(jwa.HS256(), key),
					)
				})

				It("can encode", func() {
					Expect(token.String()).To(Equal(encodedToken))
				})

				It("can decode", func() {
					decodedToken, err := jwt.Unmarshal(encodedToken)

					Expect(err).To(BeNil())
					Expect(decodedToken.Issuer()).To(Equal(token.Issuer()))
					Expect(decodedToken.ExpirationTime()).To(Equal(token.ExpirationTime()))
					Expect(decodedToken.PrivateClaim(privateClaimKey)).To(Equal(token.PrivateClaim(privateClaimKey)))
				})
			})
		})
	})

	Describe("Verifying", func() {
		var keySet *jwk.KeySet

		BeforeEach(func() {
			token, _ = jwt.Unmarshal("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjIxNDc0ODM2NDcsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlLCJpc3MiOiJqb2UifQ.xqLr3bLT45gyQjFRTNO8WPgZ1i8UFGEhIc4-A-sJzbM")

			symmetricKey, _ := base64.RawURLEncoding.DecodeString("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow")

			keySet = jwk.NewKeySet(jwk.NewKey(symmetricKey))
		})

		It("can verify", func() {
			Expect(token.Verify(keySet, jwt.DefaultVerificationConfig)).To(BeNil())
		})
	})
})
