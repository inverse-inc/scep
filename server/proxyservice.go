package scepserver

import (
	"context"
	"crypto/rsa"
	"crypto/x509"

	// "errors"

	"time"

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
	defaultCaps := []byte("Renewal\nSHA-1\nSHA-256\nAES\nDES3\nSCEPStandard\nPOSTPKIOperation")
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
	lginfo := level.Info(svc.debugLogger)

	// Create the CSR client
	client, err := NewClient(svc.url, svc.debugLogger)
	if err != nil {
		return nil, err
	}

	var respMsg *scep.PKIMessage

	for {
		// loop in case we get a PENDING response which requires
		// a manual approval.

		respBytes, err := client.PKIOperation(ctx, msg.Raw)
		if err != nil {
			return nil, errors.Wrapf(err, "PKIOperation for %s", msg.MessageType)
		}

		respMsg, err = scep.ParsePKIMessage(respBytes, scep.WithLogger(svc.debugLogger), scep.WithCACerts(msg.Recipients))
		if err != nil {
			return nil, errors.Wrapf(err, "parsing pkiMessage response %s", msg.MessageType)
		}

		switch respMsg.PKIStatus {
		case scep.FAILURE:
			return nil, errors.Errorf("%s request failed, failInfo: %s", msg.MessageType, respMsg.FailInfo)
		case scep.PENDING:
			lginfo.Log("pkiStatus", "PENDING", "msg", "sleeping for 30 seconds, then trying again.")
			time.Sleep(30 * time.Second)
			continue
		}
		lginfo.Log("pkiStatus", "SUCCESS", "msg", "server returned a certificate.")
		break // on scep.SUCCESS
	}

	// if err := respMsg.DecryptPKIEnvelope(signerCert, key); err != nil {
	// 	return errors.Wrapf(err, "decrypt pkiEnvelope, msgType: %s, status %s", msgType, respMsg.PKIStatus)
	// }

	// respCert := respMsg.CertRepMessage.Certificate
	// if err := ioutil.WriteFile(cfg.certPath, pemCert(respCert.Raw), 0666); err != nil {
	// 	return err
	// }

	// // remove self signer if used
	// if self != nil {
	// 	if err := os.Remove(cfg.selfSignPath); err != nil {
	// 		return err
	// 	}
	// }

	return msg.Raw, err

	// var msgType scep.MessageType
	// msgType = scep.PKCSReq

	// crt, err := svc.signer.SignCSR(msg.CSRReqMessage)

	// if err == nil && crt == nil {
	// 	err = errors.New("no signed certificate")
	// }
	// if err != nil {
	// 	svc.debugLogger.Log("msg", "failed to sign CSR", "err", err)
	// 	certRep, err := msg.Fail(svc.crt, svc.key, scep.BadRequest)
	// 	return certRep.Raw, err
	// }

	// certRep, err := msg.Success(svc.crt, svc.key, crt)
	// return certRep.Raw, err
}

func (svc *proxyservice) GetNextCACert(ctx context.Context) ([]byte, error) {
	panic("not implemented")
}

// NewProxyService creates a new scep proxy service
func NewProxyService(crt *x509.Certificate, key *rsa.PrivateKey, signer CSRSigner, opts ...ServiceOption) (Service, error) {
	s := &service{
		crt:         crt,
		key:         key,
		signer:      signer,
		debugLogger: log.NewNopLogger(),
	}
	for _, opt := range opts {
		if err := opt(s); err != nil {
			return nil, err
		}
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
