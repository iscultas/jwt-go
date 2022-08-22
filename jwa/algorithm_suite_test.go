package jwa_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestJWA(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "JWA Suite")
}
