package types

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"github.com/AtScaleInc/goxmldsig"
	dsigtypes "github.com/AtScaleInc/goxmldsig/types"
	"time"
)

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
	EntityID                   string            `xml:"entityID,attr"`
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

// GetLocationForBinding takes in a binding (an http method) and searches for the IdP SSO
// that supports that binding. It then returns the location (url) associated with that binding.
// If it's unable to locate the SSO with desiredBinding, it returns a non-nil error.
func (idpSSOEl *IDPSSODescriptor) GetLocationForBinding(desiredBinding string) (string, error) {
	for _, SSOS := range idpSSOEl.SingleSignOnServices {
		if binding := SSOS.Binding; binding == desiredBinding {
			return SSOS.Location, nil
		}
	}
	return "", fmt.Errorf("No SSOBinding found for %v", desiredBinding)
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
			certData, err := base64.StdEncoding.DecodeString(xcert.Data)
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
	XMLName  xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata SingleLogoutService"`
	Binding  string   `xml:"Binding,attr"`
	Location string   `xml:"Location,attr"`
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
