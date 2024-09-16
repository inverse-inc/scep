package scepserver

import (
	"context"
	"crypto/rsa"
	"crypto/x509"

	// "errors"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/log/level"
	"github.com/inverse-inc/scep/scep"
	"github.com/pkg/errors"
)

type proxyservice struct {
	// The service certificate and key for SCEP exchanges. These are
	// quite likely the same as the CA keypair but may be its own SCEP
	// specific keypair in the case of e.g. RA (proxy) operation.
	crt *x509.Certificate
	key *rsa.PrivateKey

	// Optional additional CA certificates for e.g. RA (proxy) use.
	// Only used in this service when responding to GetCACert.
	addlCa []*x509.Certificate

	// The (chainable) CSR signing function. Intended to handle all
	// SCEP request functionality such as CSR & challenge checking, CA
	// issuance, RA proxying, etc.
	signer CSRSigner

	/// info logging is implemented in the service middleware layer.
	debugLogger log.Logger

	// The URL where the SCEP request needs to be proxy
	url string
}

func (svc *proxyservice) GetCACaps(ctx context.Context) ([]byte, error) {
	defaultCaps := []byte("Renewal\nSHA-1\nSHA-256\nAES\nSCEPStandard\nPOSTPKIOperation")
	return defaultCaps, nil
}

func (svc *proxyservice) GetCACert(ctx context.Context, _ string) ([]byte, int, error) {
	// Create the CSR client
	client, err := NewClient(svc.url, svc.debugLogger)
	if err != nil {
		return nil, 0, err
	}

	// Get the CA from the remote SCEP server
	resp, certNum, err := client.GetCACert(ctx, "SCEP Proxy")
	return resp, certNum, err
}

func (svc *proxyservice) PKIOperation(ctx context.Context, data []byte) ([]byte, error) {
	msg, err := scep.ParsePKIMessage(data, scep.WithLogger(svc.debugLogger))
	if err != nil {
		return nil, err
	}

	// Create the CSR client
	client, err := NewClient(svc.url, svc.debugLogger)
	if err != nil {
		return nil, err
	}

	respBytes, err := client.PKIOperation(ctx, data)
	if err != nil {
		return nil, errors.Wrapf(err, "PKIOperation for %s", msg.MessageType)
	}
	return respBytes, err
}

func (svc *proxyservice) GetNextCACert(ctx context.Context) ([]byte, error) {
	panic("not implemented")
}

// NewProxyService creates a new scep proxy service
func NewProxyService(crt *x509.Certificate, key *rsa.PrivateKey, signer CSRSigner, opts ...ServiceOption) (Service, error) {
	s := &proxyservice{
		crt:         crt,
		key:         key,
		signer:      signer,
		debugLogger: log.NewNopLogger(),
	}

	return s, nil
}

// Client is a SCEP Client
type Client interface {
	Service
	Supports(cap string) bool
}

// New creates a SCEP Client.
func NewClient(
	serverURL string,
	logger log.Logger,
) (Client, error) {
	endpoints, err := MakeClientEndpoints(serverURL)
	if err != nil {
		return nil, err
	}
	logger = level.Info(logger)
	endpoints.GetEndpoint = EndpointLoggingMiddleware(logger)(endpoints.GetEndpoint)
	endpoints.PostEndpoint = EndpointLoggingMiddleware(logger)(endpoints.PostEndpoint)
	return endpoints, nil
}

func (svc *proxyservice) WithAddProxy(ctx context.Context, url string) {
	svc.url = url
}
