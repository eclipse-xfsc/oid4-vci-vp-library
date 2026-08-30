package credential

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func Test_OfferResolveParams(t *testing.T) {
	const offerLink = "openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22http%3A%2F%2F192.168.100.181%3A2000%2Foid4vci%2Fe73c9a3b-ec91-47a2-8a37-5dc6cc14becd%22%2C%22credential_configuration_ids%22%3A%5B%22UniversityDegreeCredential%22%5D%2C%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%22140566434786620787671313%22%7D%7D%7D"

	offer := CredentialOffer{
		CredentialOffer: offerLink,
	}

	off, err := offer.GetOfferParameters()
	if err != nil {
		t.Fatalf("GetOfferParameters() returned error: %v", err)
	}

	if off == nil {
		t.Fatal("expected credential offer parameters")
	}

	if off.CredentialIssuer != "http://192.168.100.181:2000/oid4vci/e73c9a3b-ec91-47a2-8a37-5dc6cc14becd" {
		t.Errorf(
			"unexpected credential issuer: %s",
			off.CredentialIssuer,
		)
	}

	if len(off.CredentialConfigurationIDs) != 1 {
		t.Fatalf(
			"expected one credential configuration id, got %d",
			len(off.CredentialConfigurationIDs),
		)
	}

	if off.CredentialConfigurationIDs[0] != "UniversityDegreeCredential" {
		t.Errorf(
			"unexpected credential configuration id: %s",
			off.CredentialConfigurationIDs[0],
		)
	}

	if off.Grants == nil {
		t.Fatal("expected grants")
	}

	if off.Grants.PreAuthorizedCode == nil {
		t.Fatal("expected pre-authorized code grant")
	}

	if off.Grants.PreAuthorizedCode.PreAuthorizedCode != "140566434786620787671313" {
		t.Errorf(
			"unexpected pre-authorized code: %s",
			off.Grants.PreAuthorizedCode.PreAuthorizedCode,
		)
	}

	offering, err := off.CreateOfferLink()
	if err != nil {
		t.Fatalf("CreateOfferLink() returned error: %v", err)
	}

	offeringParams, err := offering.GetOfferParameters()
	if err != nil {
		t.Fatalf("GetOfferParameters() after CreateOfferLink() returned error: %v", err)
	}

	if offeringParams.CredentialIssuer != off.CredentialIssuer {
		t.Errorf(
			"credential issuer mismatch: got %s, want %s",
			offeringParams.CredentialIssuer,
			off.CredentialIssuer,
		)
	}

	if offeringParams.Grants == nil ||
		offeringParams.Grants.PreAuthorizedCode == nil {

		t.Fatal("expected pre-authorized code grant after round trip")
	}

	if offeringParams.Grants.PreAuthorizedCode.PreAuthorizedCode !=
		off.Grants.PreAuthorizedCode.PreAuthorizedCode {

		t.Errorf(
			"pre-authorized code mismatch: got %s, want %s",
			offeringParams.Grants.PreAuthorizedCode.PreAuthorizedCode,
			off.Grants.PreAuthorizedCode.PreAuthorizedCode,
		)
	}
}

func Test_OfferResolveParams2(t *testing.T) {
	const offerLink = "openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fcloud-wallet.xfsc.dev%22%2C%22credential_configuration_ids%22%3A%5B%22DeveloperCredential%22%5D%2C%22grants%22%3A%7B%22authorization_code%22%3A%7B%22issuer_state%22%3A%22%22%7D%2C%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%22BeAzFDQJkTdyQihyRh6w%22%2C%22tx_code%22%3A%7B%22input_mode%22%3A%22text%22%2C%22length%22%3A5%2C%22description%22%3A%22Test%22%7D%7D%7D%7D"

	offer := CredentialOffer{
		CredentialOffer: offerLink,
	}

	off, err := offer.GetOfferParameters()
	if err != nil {
		t.Fatalf("GetOfferParameters() returned error: %v", err)
	}

	if off.CredentialIssuer != "https://cloud-wallet.xfsc.dev" {
		t.Errorf(
			"unexpected credential issuer: %s",
			off.CredentialIssuer,
		)
	}

	if len(off.CredentialConfigurationIDs) != 1 ||
		off.CredentialConfigurationIDs[0] != "DeveloperCredential" {

		t.Fatalf(
			"unexpected credential configuration ids: %v",
			off.CredentialConfigurationIDs,
		)
	}

	if off.Grants == nil {
		t.Fatal("expected grants")
	}

	if off.Grants.AuthorizationCode == nil {
		t.Fatal("expected authorization code grant")
	}

	if off.Grants.PreAuthorizedCode == nil {
		t.Fatal("expected pre-authorized code grant")
	}

	preAuthorizedCode := off.Grants.PreAuthorizedCode

	if preAuthorizedCode.PreAuthorizedCode != "BeAzFDQJkTdyQihyRh6w" {
		t.Errorf(
			"unexpected pre-authorized code: %s",
			preAuthorizedCode.PreAuthorizedCode,
		)
	}

	if preAuthorizedCode.TxCode == nil {
		t.Fatal("expected tx_code")
	}

	if preAuthorizedCode.TxCode.InputMode != TxCodeInputModeText {
		t.Errorf(
			"unexpected tx_code input_mode: %s",
			preAuthorizedCode.TxCode.InputMode,
		)
	}

	if preAuthorizedCode.TxCode.Length != 5 {
		t.Errorf(
			"unexpected tx_code length: %d",
			preAuthorizedCode.TxCode.Length,
		)
	}

	if preAuthorizedCode.TxCode.Description != "Test" {
		t.Errorf(
			"unexpected tx_code description: %s",
			preAuthorizedCode.TxCode.Description,
		)
	}

	// Test semantic round trip instead of comparing the encoded URL.
	offering, err := off.CreateOfferLink()
	if err != nil {
		t.Fatalf("CreateOfferLink() returned error: %v", err)
	}

	roundTrip, err := offering.GetOfferParameters()
	if err != nil {
		t.Fatalf("round trip GetOfferParameters() returned error: %v", err)
	}

	if roundTrip.CredentialIssuer != off.CredentialIssuer {
		t.Errorf(
			"credential issuer mismatch: got %s, want %s",
			roundTrip.CredentialIssuer,
			off.CredentialIssuer,
		)
	}

	if roundTrip.Grants == nil ||
		roundTrip.Grants.PreAuthorizedCode == nil {

		t.Fatal("expected pre-authorized grant after round trip")
	}

	if roundTrip.Grants.PreAuthorizedCode.PreAuthorizedCode !=
		off.Grants.PreAuthorizedCode.PreAuthorizedCode {

		t.Errorf(
			"pre-authorized code mismatch: got %s, want %s",
			roundTrip.Grants.PreAuthorizedCode.PreAuthorizedCode,
			off.Grants.PreAuthorizedCode.PreAuthorizedCode,
		)
	}
}

func Test_GetIssuerMetadata(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/.well-known/openid-credential-issuer" {
				t.Errorf(
					"unexpected metadata path: %s",
					r.URL.Path,
				)
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)

			metadata := IssuerMetadata{
				CredentialIssuer:                  "test",
				CredentialEndpoint:                "https://example.com/credential",
				CredentialConfigurationsSupported: map[string]CredentialConfiguration{},
			}

			b, err := json.Marshal(metadata)
			if err != nil {
				t.Fatalf("could not marshal metadata: %v", err)
			}

			if _, err := w.Write(b); err != nil {
				t.Fatalf("could not write response: %v", err)
			}
		},
	))
	defer srv.Close()

	offeringParams := CredentialOfferParameters{
		CredentialIssuer: srv.URL,
	}

	metadata, err := offeringParams.GetIssuerMetadata()
	if err != nil {
		t.Fatalf("GetIssuerMetadata() returned error: %v", err)
	}

	if metadata.CredentialIssuer != "test" {
		t.Errorf(
			"unexpected credential issuer: %s",
			metadata.CredentialIssuer,
		)
	}
}

func Test_CredentialOfferParametersValidate(t *testing.T) {
	tests := []struct {
		name    string
		offer   CredentialOfferParameters
		wantErr bool
	}{
		{
			name: "valid",
			offer: CredentialOfferParameters{
				CredentialIssuer: "https://issuer.example",
				CredentialConfigurationIDs: []string{
					"UniversityDegreeCredential",
				},
			},
		},
		{
			name: "missing issuer",
			offer: CredentialOfferParameters{
				CredentialConfigurationIDs: []string{
					"UniversityDegreeCredential",
				},
			},
			wantErr: true,
		},
		{
			name: "missing credential configuration ids",
			offer: CredentialOfferParameters{
				CredentialIssuer: "https://issuer.example",
			},
			wantErr: true,
		},
		{
			name: "empty credential configuration id",
			offer: CredentialOfferParameters{
				CredentialIssuer: "https://issuer.example",
				CredentialConfigurationIDs: []string{
					"",
				},
			},
			wantErr: true,
		},
		{
			name: "duplicate credential configuration id",
			offer: CredentialOfferParameters{
				CredentialIssuer: "https://issuer.example",
				CredentialConfigurationIDs: []string{
					"UniversityDegreeCredential",
					"UniversityDegreeCredential",
				},
			},
			wantErr: true,
		},
		{
			name: "missing pre-authorized code",
			offer: CredentialOfferParameters{
				CredentialIssuer: "https://issuer.example",
				CredentialConfigurationIDs: []string{
					"UniversityDegreeCredential",
				},
				Grants: &Grants{
					PreAuthorizedCode: &PreAuthorizedCode{},
				},
			},
			wantErr: true,
		},
		{
			name: "valid tx code",
			offer: CredentialOfferParameters{
				CredentialIssuer: "https://issuer.example",
				CredentialConfigurationIDs: []string{
					"UniversityDegreeCredential",
				},
				Grants: &Grants{
					PreAuthorizedCode: &PreAuthorizedCode{
						PreAuthorizedCode: "123",
						TxCode: &TxCode{
							InputMode:   TxCodeInputModeNumeric,
							Length:      6,
							Description: "Enter code",
						},
					},
				},
			},
		},
		{
			name: "invalid tx code input mode",
			offer: CredentialOfferParameters{
				CredentialIssuer: "https://issuer.example",
				CredentialConfigurationIDs: []string{
					"UniversityDegreeCredential",
				},
				Grants: &Grants{
					PreAuthorizedCode: &PreAuthorizedCode{
						PreAuthorizedCode: "123",
						TxCode: &TxCode{
							InputMode: TxCodeInputMode("invalid"),
						},
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.offer.Validate()

			if tt.wantErr && err == nil {
				t.Fatal("expected error")
			}

			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
