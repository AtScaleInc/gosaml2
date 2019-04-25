package types

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"github.com/AtScaleInc/goxmldsig"
	dsigtypes "github.com/AtScaleInc/goxmldsig/types"
	"strings"
	"time"
)

// Redeclaring consts here (they're present in xml_constants.go) because they're declared in a
// separate package within the same repo, which would lead to a circular import if I attempted
// to import them here.
const (
	BindingHttpPost     = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
	BindingHttpRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
)

var frontChannelBindingsSet = map[string]bool{
	BindingHttpPost:     true,
	BindingHttpRedirect: true,
}

type EntityDescriptor struct {
	XMLName    xml.Name  `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
	ValidUntil time.Time `xml:"validUntil,attr"`
	// SAML 2.0 8.3.6 Entity Identifier could be used to represent issuer
	EntityID         string            `xml:"entityID,attr"`
	SPSSODescriptor  *SPSSODescriptor  `xml:"SPSSODescriptor,omitempty"`
	IDPSSODescriptor *IDPSSODescriptor `xml:"IDPSSODescriptor,omitempty"`
	Extensions       *Extensions       `xml:"Extensions,omitempty"`
}

type Endpoint struct {
	Binding          string `xml:"Binding,attr"`
	Location         string `xml:"Location,attr"`
	ResponseLocation string `xml:"ResponseLocation,attr,omitempty"`
}

type IndexedEndpoint struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
	Index    int    `xml:"index,attr"`
}

type SPSSODescriptor struct {
	XMLName                    xml.Name          `xml:"urn:oasis:names:tc:SAML:2.0:metadata SPSSODescriptor"`
	AuthnRequestsSigned        bool              `xml:"AuthnRequestsSigned,attr"`
	WantAssertionsSigned       bool              `xml:"WantAssertionsSigned,attr"`
	ProtocolSupportEnumeration string            `xml:"protocolSupportEnumeration,attr"`
	KeyDescriptors             []KeyDescriptor   `xml:"KeyDescriptor"`
	SingleLogoutServices       []Endpoint        `xml:"SingleLogoutService"`
	NameIDFormats              []string          `xml:"NameIDFormat"`
	AssertionConsumerServices  []IndexedEndpoint `xml:"AssertionConsumerService"`
	Extensions                 *Extensions       `xml:"Extensions,omitempty"`
}

type IDPSSODescriptor struct {
	XMLName                 xml.Name              `xml:"urn:oasis:names:tc:SAML:2.0:metadata IDPSSODescriptor"`
	WantAuthnRequestsSigned bool                  `xml:"WantAuthnRequestsSigned,attr"`
	EntityID                string                `xml:"entityID,attr"`
	KeyDescriptors          []KeyDescriptor       `xml:"KeyDescriptor"`
	NameIDFormats           []NameIDFormat        `xml:"NameIDFormat"`
	SingleSignOnServices    []SingleSignOnService `xml:"SingleSignOnService"`
	SingleLogoutServices    []SingleLogoutService `xml:"SingleLogoutService"`
	Attributes              []Attribute           `xml:"Attribute"`
	Extensions              *Extensions           `xml:"Extensions,omitempty"`
}

// GetSignOnLocationForBinding takes in a binding (an http method) and searches for the IdP SSO
// that supports that binding. It then returns the location (url) associated with that binding.
// If it's unable to locate the SSO with desiredBinding, it returns a non-nil error.
func (idpSSOEl *IDPSSODescriptor) GetSignOnLocationForBinding(desiredBinding string) (string, error) {
	for _, SSOS := range idpSSOEl.SingleSignOnServices {
		if binding := SSOS.Binding; binding == desiredBinding {
			return SSOS.Location, nil
		}
	}
	return "", fmt.Errorf("No SSO service found for binding: %v", desiredBinding)
}

// FrontChannelBindingExists will return a bool corresponding to whether or not the IDP
// has an SLO service with either the POST or Redirect binding
func (idpSSOEl *IDPSSODescriptor) FrontChannelBindingExists() bool {
	for _, SLOS := range idpSSOEl.SingleLogoutServices {
		if frontChannelBindingsSet[SLOS.Binding] {
			return true
		}
	}
	return false
}

// GetSLOService returns the first slo service found for the idp that has a front channel binding.
// If not found, it returns a non nil error.
func (idpSSOEl *IDPSSODescriptor) GetFrontChannelSLOS() (*SingleLogoutService, error) {
	for _, SLOS := range idpSSOEl.SingleLogoutServices {
		if frontChannelBindingsSet[SLOS.Binding] {
			return &SLOS, nil
		}
	}
	return nil, fmt.Errorf("Unable to find SLOS with front channel binding")
}

// ParseCerts iterates through all the KeyDescriptors of the IdPSSODescriptor,
// ensuring they are non-empty and can be decoded using the standard base64 decode method.
// After the cert passes all checks, it's appended to a cert store. The certStore
// and any error that was encountered are returned
// Assumes the struct fields have been instantiated.
func (idpSSOEl *IDPSSODescriptor) ParseCerts() (dsig.MemoryX509CertificateStore, error) {
	certStore := dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{},
	}

	for _, kd := range idpSSOEl.KeyDescriptors {
		for idx, xcert := range kd.KeyInfo.X509Data.X509Certificates {
			// it will be base64 so we'll decode
			if xcert.Data == "" {
				return certStore, fmt.Errorf("x509 certificate(%d) empty", idx)
			}
			certData, err := base64.StdEncoding.DecodeString(strings.TrimSpace(xcert.Data))
			if err != nil {
				return certStore, fmt.Errorf("Error decoding certificate(%d) base64 data -- may be malformed. Raw error: %v", idx, err.Error())
			}
			idpCert, err := x509.ParseCertificate(certData)
			if err != nil {
				return certStore, err
			}
			certStore.Roots = append(certStore.Roots, idpCert)
		}
	}
	return certStore, nil
}

type KeyDescriptor struct {
	XMLName           xml.Name           `xml:"urn:oasis:names:tc:SAML:2.0:metadata KeyDescriptor"`
	Use               string             `xml:"use,attr"`
	KeyInfo           dsigtypes.KeyInfo  `xml:"KeyInfo"`
	EncryptionMethods []EncryptionMethod `xml:"EncryptionMethod"`
}

type NameIDFormat struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata NameIDFormat"`
	Value   string   `xml:",chardata"`
}

type SingleSignOnService struct {
	XMLName  xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata SingleSignOnService"`
	Binding  string   `xml:"Binding,attr"`
	Location string   `xml:"Location,attr"`
}

type SingleLogoutService struct {
	XMLName          xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata SingleLogoutService"`
	Binding          string   `xml:"Binding,attr"`
	Location         string   `xml:"Location,attr"`
	ResponseLocation string   `xml:"ResponseLocation,attr"` // where to send logout response in IdP init logout
}

type SigningMethod struct {
	Algorithm  string `xml:",attr"`
	MinKeySize string `xml:"MinKeySize,attr,omitempty"`
	MaxKeySize string `xml:"MaxKeySize,attr,omitempty"`
}

type Extensions struct {
	DigestMethod  *DigestMethod  `xml:",omitempty"`
	SigningMethod *SigningMethod `xml:",omitempty"`
}
