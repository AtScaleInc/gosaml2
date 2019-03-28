package saml2

import (
	"encoding/base64"
	"fmt"

	dsig "github.com/AtScaleInc/goxmldsig"
)

func (sp *SAMLServiceProvider) validateLogoutRequestAttributes(request *LogoutRequest) error {
	if request.Destination != "" && request.Destination != sp.ServiceProviderSLOURL {
		return ErrInvalidValue{
			Key:      DestinationAttr,
			Expected: sp.ServiceProviderSLOURL,
			Actual:   request.Destination,
		}
	}

	if request.Version != "2.0" {
		return ErrInvalidValue{
			Reason:   ReasonUnsupported,
			Key:      "SAML version",
			Expected: "2.0",
			Actual:   request.Version,
		}
	}

	return nil
}

func (sp *SAMLServiceProvider) ValidateEncodedLogoutRequestPOST(encodedRequest string) (*LogoutRequest, error) {
	raw, err := base64.StdEncoding.DecodeString(encodedRequest)
	if err != nil {
		return nil, err
	}

	// Parse the raw request - parseResponse is generic
	doc, el, err := parseResponse(raw)
	if err != nil {
		return nil, err
	}
	fmt.Println("successfully parsed the logout REQUEST")

	var requestSignatureValidated bool
	fmt.Println("moving onto validating signatures on the request")
	if !sp.SkipSignatureValidation {
		el, err = sp.validateElementSignature(el)
		if err == dsig.ErrMissingSignature {
			// Unfortunately we just blew away our Response
			el = doc.Root()
		} else if err != nil {
			fmt.Printf("error validating logout request sig: %v\n", err)
			return nil, err
		} else if el == nil {
			return nil, fmt.Errorf("missing transformed logout request")
		} else {
			fmt.Printf("i guess we validated it!")
			requestSignatureValidated = true
		}
	}

	decodedRequest := &LogoutRequest{}
	err = xmlUnmarshalElement(el, decodedRequest)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal logout request: %v", err)
	}
	fmt.Printf("we have unmarshalled the xml into a logout request struct")
	decodedRequest.SignatureValidated = requestSignatureValidated

	err = sp.ValidateDecodedLogoutRequest(decodedRequest)
	if err != nil {
		return nil, err
	}

	return decodedRequest, nil
}
