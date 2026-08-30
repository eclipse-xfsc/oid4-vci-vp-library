package presentation

import (
	"encoding/json"
	"testing"

	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/types"
)

func newTestCredential(format string, claims map[string]any) *types.Credential {
	return &types.Credential{Format: types.CredentialFormat(format), Json: claims}
}

func boolPtr(b bool) *bool { return &b }

func TestClaimsPathPointerResolveJSON(t *testing.T) {
	document := map[string]any{
		"degrees": []any{
			map[string]any{"type": "Bachelor"},
			map[string]any{"type": "Master"},
		},
		"nationalities": []any{"British", "Betelgeusian"},
	}

	values, err := (ClaimsPathPointer{"degrees", nil, "type"}).ResolveJSON(document)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(values) != 2 || values[0] != "Bachelor" || values[1] != "Master" {
		t.Fatalf("unexpected values: %#v", values)
	}

	values, err = (ClaimsPathPointer{"nationalities", 1}).ResolveJSON(document)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(values) != 1 || values[0] != "Betelgeusian" {
		t.Fatalf("unexpected indexed value: %#v", values)
	}
}

func TestClaimsPathPointerJSONRoundTrip(t *testing.T) {
	raw := []byte(`{"path":["degrees",null,0,"type"]}`)
	var claim ClaimQuery
	if err := json.Unmarshal(raw, &claim); err != nil {
		t.Fatal(err)
	}
	if err := claim.Path.Validate(); err != nil {
		t.Fatalf("valid pointer rejected: %v", err)
	}
	if _, ok := claim.Path[2].(float64); !ok {
		t.Fatalf("expected JSON number to decode to float64, got %T", claim.Path[2])
	}
}

func TestDCQLValidateRejectsUnknownReferences(t *testing.T) {
	q := DCQLQuery{
		Credentials: []CredentialQuery{{
			ID: "pid", Format: "dc+sd-jwt",
			Claims:    []ClaimQuery{{ID: "name", Path: ClaimsPathPointer{"given_name"}}},
			ClaimSets: [][]string{{"missing"}},
		}},
	}
	if err := q.Validate(); err == nil {
		t.Fatal("expected invalid claim_sets reference to fail")
	}

	q = DCQLQuery{
		Credentials:    []CredentialQuery{{ID: "pid", Format: "dc+sd-jwt"}},
		CredentialSets: []CredentialSetQuery{{Options: [][]string{{"missing"}}}},
	}
	if err := q.Validate(); err == nil {
		t.Fatal("expected invalid credential_sets reference to fail")
	}
}

func TestEvaluateCredentialQueryTypedValues(t *testing.T) {
	cred := newTestCredential("ldp_vc", map[string]any{
		"credentialSubject": map[string]any{"age": 25.0, "active": true},
	})
	q := CredentialQuery{
		ID: "cred", Format: "ldp_vc",
		Claims: []ClaimQuery{
			{Path: ClaimsPathPointer{"credentialSubject", "age"}, Values: []any{25.0}},
			{Path: ClaimsPathPointer{"credentialSubject", "active"}, Values: []any{true}},
		},
	}
	match, err := q.evaluateCredentialQuery(cred, string(cred.Format))
	if err != nil || !match {
		t.Fatalf("expected typed values to match; match=%v err=%v", match, err)
	}
}

func TestEvaluateCredentialQuerySDJWTMetadata(t *testing.T) {
	cred := newTestCredential("dc+sd-jwt", map[string]any{
		"vct":        "https://credentials.example.com/identity_credential",
		"given_name": "Arthur",
	})
	q := CredentialQuery{
		ID: "pid", Format: "dc+sd-jwt",
		Meta:   map[string]any{"vct_values": []any{"https://credentials.example.com/identity_credential"}},
		Claims: []ClaimQuery{{Path: ClaimsPathPointer{"given_name"}}},
	}
	match, err := q.evaluateCredentialQuery(cred, string(cred.Format))
	if err != nil || !match {
		t.Fatalf("expected SD-JWT metadata to match; match=%v err=%v", match, err)
	}
}

func TestDCQLQueryFilter(t *testing.T) {
	credentials := map[string]any{
		"cred-1": map[string]any{
			"issuer":            "did:example:123",
			"credentialSubject": map[string]any{"age": 30.0},
		},
	}
	query := DCQLQuery{Credentials: []CredentialQuery{{
		ID: "q1", Format: "ldp_vc",
		Claims: []ClaimQuery{{Path: ClaimsPathPointer{"credentialSubject", "age"}, Values: []any{30.0}}},
	}}}

	results, err := query.Filter(credentials)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 || len(results[0].Credentials) != 1 {
		t.Fatalf("unexpected results: %#v", results)
	}
}

func TestDCQLQueryFilterNoCredentials(t *testing.T) {
	q := DCQLQuery{}
	if _, err := q.Filter(nil); err == nil {
		t.Fatal("expected empty DCQL query to fail")
	}
}
