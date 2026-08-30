package presentation

import "testing"

func TestAuthorizationRequestFinalDCQLValidation(t *testing.T) {
	req := AuthorizationRequest{
		ClientID:     "x509_san_dns:verifier.example",
		ResponseType: "vp_token",
		ResponseMode: "direct_post",
		ResponseURI:  "https://verifier.example/response",
		Nonce:        "n-123",
		DCQLQuery:    &DCQLQuery{Credentials: []CredentialQuery{{ID: "pid", Format: "dc+sd-jwt"}}},
	}
	if err := req.Validate(); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
}

func TestAuthorizationRequestRequiresQueryOrScope(t *testing.T) {
	req := AuthorizationRequest{ClientID: "client", ResponseType: "vp_token", Nonce: "n"}
	if err := req.Validate(); err == nil {
		t.Fatal("expected query/scope validation error")
	}
}
