package depot

import (
	"crypto/rsa"
	"crypto/x509"
	"math/big"
)

// Depot is a repository for managing certificates
type Depot interface {
	CA(pass []byte, options ...string) ([]*x509.Certificate, *rsa.PrivateKey, error)
	Put(name string, crt *x509.Certificate, options ...string) error
	Serial(options ...string) (*big.Int, error)
	HasCN(cn string, allowTime int, cert *x509.Certificate, revokeOldCertificate bool, options ...string) (bool, error)
}
