package depot

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"strconv"
	"strings"
	"time"

	"github.com/inverse-inc/scep/cryptoutil"
	"github.com/inverse-inc/scep/scep"
)

// Signer signs x509 certificates and stores them in a Depot
type Signer struct {
	depot            Depot
	caPass           string
	allowRenewalDays int
	validityDays     int
	profile          string
	attributes       map[string]string
}

// Option customizes Signer
type Option func(*Signer)

// NewSigner creates a new Signer
func NewSigner(depot Depot, opts ...Option) *Signer {
	s := &Signer{
		depot:            depot,
		allowRenewalDays: 14,
		validityDays:     365,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// WithAttributes specifies the attributes to use.
func WithAttributes(attribs map[string]string) Option {
	return func(s *Signer) {
		s.attributes = make(map[string]string)
		for k, v := range attribs {
			s.attributes[k] = v
		}
	}
}

// WithCAPass specifies the password to use with an encrypted CA key
func WithCAPass(pass string) Option {
	return func(s *Signer) {
		s.caPass = pass
	}
}

// WithAllowRenewalDays sets the allowable renewal time for existing certs
func WithAllowRenewalDays(r int) Option {
	return func(s *Signer) {
		s.allowRenewalDays = r
	}
}

// WithValidityDays sets the validity period new certs will use
func WithValidityDays(v int) Option {
	return func(s *Signer) {
		s.validityDays = v
	}
}

// Profile is an optional argument to NewService
// which allows setting a profile for SCEP.
func WithProfile(profile string) Option {
	return func(s *Signer) {
		s.profile = profile
	}
}

// SignCSR signs a certificate using Signer's Depot CA
func (s *Signer) SignCSR(m *scep.CSRReqMessage) (*x509.Certificate, error) {

	id, err := cryptoutil.GenerateSubjectKeyID(m.CSR.PublicKey)
	if err != nil {
		return nil, err
	}

	serial, err := s.depot.Serial(s.profile)
	if err != nil {
		return nil, err
	}
	Subject := makeSubject(m.CSR.Subject, s.attributes)
	Subject.CommonName = m.CSR.Subject.CommonName

	ExtKeyUsage := Extkeyusage(strings.Split(s.attributes["ExtendedKeyUsage"], "|"))
	KeyUsage := x509.KeyUsage(Keyusage(strings.Split(s.attributes["KeyUsage"], "|")))

	// create cert template
	v, _ := strconv.Atoi(s.attributes["Digest"])
	SignatureAlgorithm = x509.SignatureAlgorithm(v)
	tmpl := &x509.Certificate{
		SerialNumber:       serial,
		Subject:            Subject,
		NotBefore:          time.Now().Add(-600).UTC(),
		NotAfter:           time.Now().AddDate(0, 0, s.validityDays).UTC(),
		SubjectKeyId:       id,
		KeyUsage:           KeyUsage,
		ExtKeyUsage:        ExtKeyUsage,
		SignatureAlgorithm: SignatureAlgorithm,
		DNSNames:           m.CSR.DNSNames,
		EmailAddresses:     m.CSR.EmailAddresses,
		IPAddresses:        m.CSR.IPAddresses,
		URIs:               m.CSR.URIs,
		ExtraExtensions:    m.CSR.ExtraExtensions,
	}

	if len(s.attributes["OCSPUrl"]) > 0 {
		tmpl.OCSPServer = []string{s.attributes["OCSPUrl"]}
	}

	if len(s.attributes["Mail"]) > 0 {
		tmpl.EmailAddresses = []string{s.attributes["Mail"]}
	}

	caCerts, caKey, err := s.depot.CA([]byte(s.caPass), s.profile)
	if err != nil {
		return nil, err
	}

	crtBytes, err := x509.CreateCertificate(rand.Reader, tmpl, caCerts[0], m.CSR.PublicKey, caKey)
	if err != nil {
		return nil, err
	}

	crt, err := x509.ParseCertificate(crtBytes)
	if err != nil {
		return nil, err
	}

	name := certName(crt)

	// Test if this certificate is already in the CADB, revoke if needed
	// revocation is done if the validity of the existing certificate is
	// less than allowRenewalDays
	_, err = s.depot.HasCN(name, s.allowRenewalDays, crt, false, s.profile)
	if err != nil {
		s.depot.FailureNotify(crt, m, err.Error())
		return nil, err
	}

	if err := s.depot.Put(name, crt, s.profile); err != nil {
		s.depot.FailureNotify(crt, m, err.Error())
		return nil, err
	}
	s.depot.SuccessNotify(crt, m, "Great Job")
	return crt, nil
}

func certName(crt *x509.Certificate) string {
	if crt.Subject.CommonName != "" {
		return crt.Subject.CommonName
	}
	return string(crt.Signature)
}

func makeSubject(Subject pkix.Name, attributes map[string]string) pkix.Name {

	for k, v := range attributes {
		switch k {
		case "Organization":
			if len(v) > 0 {
				Subject.Organization = []string{v}
			}
		case "OrganizationalUnit":
			if len(v) > 0 {
				Subject.OrganizationalUnit = []string{v}
			}
		case "Country":
			if len(v) > 0 {
				Subject.Country = []string{v}
			}
		case "State":
			if len(v) > 0 {
				Subject.Province = []string{v}
			}
		case "Locality":
			if len(v) > 0 {
				Subject.Locality = []string{v}
			}
		case "StreetAddress":
			if len(v) > 0 {
				Subject.StreetAddress = []string{v}
			}
		case "PostalCode":
			if len(v) > 0 {
				Subject.PostalCode = []string{v}
			}
		}
	}
	return Subject
}

func Extkeyusage(ExtendedKeyUsage []string) []x509.ExtKeyUsage {

	// Set up extra key uses for certificate
	extKeyUsage := make([]x509.ExtKeyUsage, 0)
	for _, use := range ExtendedKeyUsage {
		if use != "" {
			v, _ := strconv.Atoi(use)
			extKeyUsage = append(extKeyUsage, x509.ExtKeyUsage(v))
		}
	}
	return extKeyUsage
}

func Keyusage(KeyUsage []string) int {
	keyUsage := 0
	for _, use := range KeyUsage {
		v, _ := strconv.Atoi(use)
		keyUsage = keyUsage | v
	}
	return keyUsage
}
