package credential

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func Test_OfferResolveParams(t *testing.T) {

	const offerLink = "openid-credential-offer://?credential_offer=%7B%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%22140566434786620787671313%22%2C%22user_pin_required%22%3Afalse%7D%7D%2C%22credentials%22%3A%5B%22UniversityDegreeCredential%22%5D%2C%22credential_issuer%22%3A%22http%3A%2F%2F192.168.100.181%3A2000%2Foid4vci%2Fe73c9a3b-ec91-47a2-8a37-5dc6cc14becd%22%7D"

	offer := CredentialOffer{
		CredentialOffer: offerLink,
	}

	off, err := offer.GetOfferParameters()

	if err != nil {
		t.Error()
	}

	if off != nil {
		if off.CredentialIssuer != "http://192.168.100.181:2000/oid4vci/e73c9a3b-ec91-47a2-8a37-5dc6cc14becd" {
			t.Error()
		}

		if off.Grants.PreAuthorizedCode.PreAuthorizationCode != "140566434786620787671313" {
			t.Error()
		}
	}

	offering, err := off.CreateOfferLink()

	if err != nil {
		t.Error()
	}

	offeringParams, err := offering.GetOfferParameters()

	if err != nil {
		t.Error()
	}

	if offeringParams.CredentialIssuer != off.CredentialIssuer {
		t.Error()
	}

	if offeringParams.Grants.PreAuthorizedCode.PreAuthorizationCode != off.Grants.PreAuthorizedCode.PreAuthorizationCode {
		t.Error()
	}

}

func Test_OfferResolveParams2(t *testing.T) {

	const offerLink = "openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fcloud-wallet.xfsc.dev%22%2C%22credential_configuration_ids%22%3A%5B%22DeveloperCredential%22%5D%2C%22grants%22%3A%7B%22authorization_code%22%3A%7B%22issuer_state%22%3A%22%22%7D%2C%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%22BeAzFDQJkTdyQihyRh6w%22%2C%22tx_code%22%3A%7B%22input_mode%22%3A%22text%22%2C%22length%22%3A5%2C%22description%22%3A%22Test%22%7D%7D%7D%7D"

	offer := CredentialOffer{
		CredentialOffer: offerLink,
	}

	off, err := offer.GetOfferParameters()

	if err != nil {
		t.Error()
		return
	}

	if off != nil {
		if off.CredentialIssuer != "https://cloud-wallet.xfsc.dev" {
			t.Error()
		}

		if off.Grants.PreAuthorizedCode.PreAuthorizationCode != "BeAzFDQJkTdyQihyRh6w" {
			t.Error()
		}
	}

	offering, err := off.CreateOfferLink()

	if offering.CredentialOffer != offerLink || err != nil {
		t.Error()
	}
}

func Test_GetIssuerMetadata(t *testing.T) {

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)

		m := IssuerMetadata{
			CredentialIssuer: "test",
		}

		b, _ := json.Marshal(m)

		w.Write(b)
	}))

	offeringParams := CredentialOfferParameters{
		CredentialIssuer: srv.URL,
	}

	m, err := offeringParams.GetIssuerMetadata()

	if err != nil {
		t.Error()
	}

	if m.CredentialIssuer != "test" {
		t.Error()
	}

}
