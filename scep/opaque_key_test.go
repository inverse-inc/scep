package scep_test

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"io"
	"math/big"
	"testing"
	"time"

	"github.com/inverse-inc/scep/scep"
)

// opaqueKey hides the *rsa.PrivateKey behind crypto.Signer and
// crypto.Decrypter, like a key held in an HSM.
type opaqueKey struct{ k scep.PrivateKey }

func (o opaqueKey) Public() crypto.PublicKey { return o.k.Public() }
func (o opaqueKey) Sign(r io.Reader, d []byte, opts crypto.SignerOpts) ([]byte, error) {
	return o.k.Sign(r, d, opts)
}
func (o opaqueKey) Decrypt(r io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	return o.k.Decrypt(r, msg, opts)
}

// A SCEP server whose CA key can't be exported decrypts the PKCSReq and
// signs the CertRep, and the client decrypts the issued certificate.
func TestOpaqueCAKey(t *testing.T) {
	cacert, rsaKey := createCaCertWithKeyUsage(t, x509.KeyUsageCertSign|x509.KeyUsageKeyEncipherment)
	testCAKey(t, cacert, opaqueKey{rsaKey})
}

// The same flow with a regular RSA key.
func TestRSACAKey(t *testing.T) {
	cacert, rsaKey := createCaCertWithKeyUsage(t, x509.KeyUsageCertSign|x509.KeyUsageKeyEncipherment)
	testCAKey(t, cacert, rsaKey)
}

func testCAKey(t *testing.T, cacert *x509.Certificate, cakey scep.PrivateKey) {

	key, err := newRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	derBytes, err := newCSR(key, "john.doe@example.com", "US", "opaque-ca-key")
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(derBytes)
	if err != nil {
		t.Fatal(err)
	}
	clientcert, clientkey := loadClientCredentials(t)
	pkcsreq, err := scep.NewCSRRequest(csr, &scep.PKIMessage{
		MessageType: scep.PKCSReq,
		Recipients:  []*x509.Certificate{cacert},
		SignerCert:  clientcert,
		SignerKey:   clientkey,
	})
	if err != nil {
		t.Fatal(err)
	}

	msg := testParsePKIMessage(t, pkcsreq.Raw)
	if err := msg.DecryptPKIEnvelope(cacert, cakey); err != nil {
		t.Fatalf("DecryptPKIEnvelope with an opaque CA key: %v", err)
	}
	if msg.CSRReqMessage.CSR.Subject.CommonName != "opaque-ca-key" {
		t.Fatalf("decrypted CSR CN %q", msg.CSRReqMessage.CSR.Subject.CommonName)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(5),
		Subject:      csr.Subject,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().AddDate(1, 0, 0),
	}
	crtBytes, err := x509.CreateCertificate(rand.Reader, tmpl, cacert, csr.PublicKey, cakey)
	if err != nil {
		t.Fatal(err)
	}
	crt, err := x509.ParseCertificate(crtBytes)
	if err != nil {
		t.Fatal(err)
	}
	certRep, err := msg.Success(cacert, cakey, crt)
	if err != nil {
		t.Fatalf("Success with an opaque CA key: %v", err)
	}

	rep := testParsePKIMessage(t, certRep.Raw)
	if err := rep.DecryptPKIEnvelope(clientcert, clientkey); err != nil {
		t.Fatalf("client decrypting the CertRep: %v", err)
	}
	if got := rep.CertRepMessage.Certificate; got == nil || got.SerialNumber.Cmp(big.NewInt(5)) != 0 {
		t.Fatalf("CertRep certificate %v", got)
	}

	if _, err := msg.Fail(cacert, cakey, scep.BadRequest); err != nil {
		t.Fatalf("Fail with an opaque CA key: %v", err)
	}
}
