// Package csrverifier defines an interface for CSR verification.
package csrverifier

import (
	"crypto/x509"
	"errors"

	"github.com/inverse-inc/scep/scep"
	scepserver "github.com/inverse-inc/scep/server"
)

// CSRVerifier verifies the raw decrypted CSR.
type CSRVerifier interface {
	Verify(*scep.CSRReqMessage) (bool, error)
}

// Middleware wraps next in a CSRSigner that runs verifier
func Middleware(verifier CSRVerifier, next scepserver.CSRSigner) scepserver.CSRSignerFunc {
	return func(m *scep.CSRReqMessage) (*x509.Certificate, error) {
		ok, err := verifier.Verify(m)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, errors.New("CSR verify failed")
		}
		return next.SignCSR(m)
	}
}
