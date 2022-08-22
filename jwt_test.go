package jwt_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/iscultas/jwt-go"
	"github.com/iscultas/jwt-go/jwa"
)

var _ = Describe("JWT", func() {
	var jwt_ *jwt.Jwt

	Describe("Encoding JWT usign JWS Compact Serialization", func() {
		Context("Without signature or encryption", func() {
			BeforeEach(func() {
				jwt_ = jwt.NewJwt().SetSubject("1234567890")
			})

			It("can encode", func() {
				Expect(jwt_.String()).To(Equal("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0."))
			})
		})

		Context("With signature", func() {
			BeforeEach(func() {
				jwt_ = jwt.NewJwt().SetSubject("1234567890").Sign(jwa.HS256([]byte("test")))
			})

			It("can encode", func() {
				Expect(jwt_.String()).To(Equal("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.2gSBz9EOsQRN9I-3iSxJoFt7NtgV6Rm0IL6a8CAwl3Q"))
			})
		})
	})
})
