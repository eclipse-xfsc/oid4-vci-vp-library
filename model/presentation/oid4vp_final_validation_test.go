package presentation

import (
	"encoding/base64"
	"testing"
)

func TestOID4VPFinalDCQLRequiresMeta(t *testing.T) {
	q := DCQLQuery{Credentials: []CredentialQuery{{ID: "pid", Format: "jwt_vc_json"}}}
	if q.Validate() == nil {
		t.Fatal("expected missing meta to fail")
	}
}
func TestOID4VPFinalSDJWTRequiresVCTValues(t *testing.T) {
	q := DCQLQuery{Credentials: []CredentialQuery{{ID: "pid", Format: "dc+sd-jwt", Meta: map[string]any{}}}}
	if q.Validate() == nil {
		t.Fatal("expected missing vct_values to fail")
	}
}
func TestOID4VPFinalRejectsDuplicateClaimPaths(t *testing.T) {
	q := DCQLQuery{Credentials: []CredentialQuery{{ID: "pid", Format: "jwt_vc_json", Meta: map[string]any{}, Claims: []ClaimQuery{{Path: ClaimsPathPointer{"credentialSubject", "name"}}, {Path: ClaimsPathPointer{"credentialSubject", "name"}}}}}}
	if q.Validate() == nil {
		t.Fatal("expected duplicate claim path to fail")
	}
}
func TestOID4VPFinalTransactionDataCredentialIDs(t *testing.T) {
	raw := base64.RawURLEncoding.EncodeToString([]byte(`{"type":"example","credential_ids":["pid"]}`))
	r := AuthorizationRequest{ClientID: "client", ResponseType: "vp_token", Nonce: "nonce", DCQLQuery: &DCQLQuery{Credentials: []CredentialQuery{{ID: "pid", Format: "jwt_vc_json", Meta: map[string]any{}}}}, TransactionData: []string{raw}}
	if err := r.Validate(); err != nil {
		t.Fatalf("valid transaction data rejected: %v", err)
	}
}
func TestOID4VPFinalRequiresStateWithoutHolderBinding(t *testing.T) {
	no := false
	r := AuthorizationRequest{ClientID: "client", ResponseType: "vp_token", Nonce: "nonce", DCQLQuery: &DCQLQuery{Credentials: []CredentialQuery{{ID: "pid", Format: "jwt_vc_json", Meta: map[string]any{}, RequireCryptographicHolderBinding: &no}}}}
	if r.Validate() == nil {
		t.Fatal("expected state requirement")
	}
}
