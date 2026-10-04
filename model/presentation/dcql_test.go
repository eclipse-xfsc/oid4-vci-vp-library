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
			ID: "pid", Format: types.JWTVC, Meta: map[string]any{},
			Claims:    []ClaimQuery{{ID: "name", Path: ClaimsPathPointer{"given_name"}}},
			ClaimSets: [][]string{{"missing"}},
		}},
	}
	if err := q.Validate(); err == nil {
		t.Fatal("expected invalid claim_sets reference to fail")
	}

	q = DCQLQuery{
		Credentials:    []CredentialQuery{{ID: "pid", Format: types.JWTVC, Meta: map[string]any{}}},
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
		ID: "cred", Format: types.LDPVC, Meta: map[string]any{},
		Claims: []ClaimQuery{
			{Path: ClaimsPathPointer{"credentialSubject", "age"}, Values: []any{25.0}},
			{Path: ClaimsPathPointer{"credentialSubject", "active"}, Values: []any{true}},
		},
	}
	match, err := q.evaluateCredentialQuery(cred)
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
		ID: "pid", Format: types.SDJWT,
		Meta:   map[string]any{"vct_values": []any{"https://credentials.example.com/identity_credential"}},
		Claims: []ClaimQuery{{Path: ClaimsPathPointer{"given_name"}}},
	}
	match, err := q.evaluateCredentialQuery(cred)
	if err != nil || !match {
		t.Fatalf("expected SD-JWT metadata to match; match=%v err=%v", match, err)
	}
}

func TestDCQLQueryFilter(t *testing.T) {
	credentials := map[string]any{
		"cred-1": map[string]any{
			"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
			"type":              []any{"VerifiableCredential"},
			"issuer":            "did:example:123",
			"credentialSubject": map[string]any{"age": 30.0},
		},
	}
	query := DCQLQuery{Credentials: []CredentialQuery{{
		ID: "q1", Format: types.LDPVC, Meta: map[string]any{},
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

func TestEvaluateCredentialQueryRejectsDifferentFormat(t *testing.T) {
	cred := newTestCredential(string(types.LDPVC), map[string]any{
		"credentialSubject": map[string]any{"age": 42.0},
	})
	q := CredentialQuery{ID: "pid", Format: types.JWTVC, Meta: map[string]any{}}

	match, err := q.evaluateCredentialQuery(cred)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if match {
		t.Fatal("expected credential with a different format not to match")
	}
}

func TestEvaluateCredentialQueryFiltersByClaimValue(t *testing.T) {
	cred := newTestCredential(string(types.LDPVC), map[string]any{
		"credentialSubject": map[string]any{"age": 42.0, "name": "Arthur"},
	})
	q := CredentialQuery{
		ID: "person", Format: types.LDPVC, Meta: map[string]any{},
		Claims: []ClaimQuery{{Path: ClaimsPathPointer{"credentialSubject", "age"}, Values: []any{42.0}}},
	}

	match, err := q.evaluateCredentialQuery(cred)
	if err != nil || !match {
		t.Fatalf("expected age=42 to match; match=%v err=%v", match, err)
	}

	q.Claims[0].Values = []any{30.0}
	match, err = q.evaluateCredentialQuery(cred)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if match {
		t.Fatal("expected age=30 not to match")
	}
}

func TestEvaluateCredentialQueryRequiresClaim(t *testing.T) {
	cred := newTestCredential(string(types.LDPVC), map[string]any{
		"credentialSubject": map[string]any{"name": "Arthur"},
	})
	q := CredentialQuery{
		ID: "person", Format: types.LDPVC, Meta: map[string]any{},
		Claims: []ClaimQuery{{Path: ClaimsPathPointer{"credentialSubject", "age"}}},
	}

	match, err := q.evaluateCredentialQuery(cred)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if match {
		t.Fatal("credential without requested claim must not match")
	}
}

func TestEvaluateCredentialQueryAllowsOneOfValues(t *testing.T) {
	cred := newTestCredential(string(types.LDPVC), map[string]any{
		"credentialSubject": map[string]any{"country": "DE"},
	})
	q := CredentialQuery{
		ID: "country", Format: types.LDPVC, Meta: map[string]any{},
		Claims: []ClaimQuery{{
			Path: ClaimsPathPointer{"credentialSubject", "country"}, Values: []any{"DE", "FR"},
		}},
	}

	match, err := q.evaluateCredentialQuery(cred)
	if err != nil || !match {
		t.Fatalf("expected DE to match one of [DE, FR]; match=%v err=%v", match, err)
	}
}

func TestEvaluateCredentialQueryMatchesAllClaims(t *testing.T) {
	cred := newTestCredential(string(types.LDPVC), map[string]any{
		"credentialSubject": map[string]any{"age": 42.0, "active": true},
	})
	q := CredentialQuery{
		ID: "person", Format: types.LDPVC, Meta: map[string]any{},
		Claims: []ClaimQuery{
			{Path: ClaimsPathPointer{"credentialSubject", "age"}, Values: []any{42.0}},
			{Path: ClaimsPathPointer{"credentialSubject", "active"}, Values: []any{true}},
		},
	}

	match, err := q.evaluateCredentialQuery(cred)
	if err != nil || !match {
		t.Fatalf("expected all claims to match; match=%v err=%v", match, err)
	}

	q.Claims[1].Values = []any{false}
	match, err = q.evaluateCredentialQuery(cred)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if match {
		t.Fatal("expected credential not to match when one claim fails")
	}
}

func TestEvaluateCredentialQueryClaimSets(t *testing.T) {
	cred := newTestCredential(string(types.LDPVC), map[string]any{
		"credentialSubject": map[string]any{"given_name": "Arthur", "age": 42.0},
	})
	q := CredentialQuery{
		ID: "person", Format: types.LDPVC, Meta: map[string]any{},
		Claims: []ClaimQuery{
			{ID: "name", Path: ClaimsPathPointer{"credentialSubject", "given_name"}, Values: []any{"Arthur"}},
			{ID: "age", Path: ClaimsPathPointer{"credentialSubject", "age"}, Values: []any{42.0}},
			{ID: "country", Path: ClaimsPathPointer{"credentialSubject", "country"}, Values: []any{"DE"}},
		},
		ClaimSets: [][]string{{"name", "country"}, {"name", "age"}},
	}

	match, err := q.evaluateCredentialQuery(cred)
	if err != nil || !match {
		t.Fatalf("expected second claim set [name, age] to match; match=%v err=%v", match, err)
	}
}

func TestEvaluateCredentialQuerySDJWTVCTMismatch(t *testing.T) {
	cred := newTestCredential(string(types.SDJWT), map[string]any{"vct": "https://example.com/employee"})
	q := CredentialQuery{
		ID: "pid", Format: types.SDJWT,
		Meta: map[string]any{"vct_values": []any{"https://example.com/pid"}},
	}

	match, err := q.evaluateCredentialQuery(cred)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if match {
		t.Fatal("expected different vct not to match")
	}
}

func TestDCQLQueryFilterReturnsMatchingCredentialID(t *testing.T) {
	credentials := map[string]any{
		"matching-credential": map[string]any{
			"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
			"type":              []any{"VerifiableCredential"},
			"issuer":            "did:example:123",
			"credentialSubject": map[string]any{"age": 42.0},
		},
		"non-matching-credential": map[string]any{
			"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
			"type":              []any{"VerifiableCredential"},
			"issuer":            "did:example:456",
			"credentialSubject": map[string]any{"age": 21.0},
		},
	}
	query := DCQLQuery{Credentials: []CredentialQuery{{
		ID: "age-query", Format: types.LDPVC, Meta: map[string]any{},
		Claims: []ClaimQuery{{Path: ClaimsPathPointer{"credentialSubject", "age"}, Values: []any{42.0}}},
	}}}

	results, err := query.Filter(credentials)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected one query result, got %d", len(results))
	}
	if results[0].Id != "age-query" {
		t.Fatalf("expected query id age-query, got %q", results[0].Id)
	}
	if len(results[0].Credentials) != 1 {
		t.Fatalf("expected exactly one credential, got %d", len(results[0].Credentials))
	}
	if _, ok := results[0].Credentials["matching-credential"]; !ok {
		t.Fatal("expected matching-credential in result")
	}
	if _, ok := results[0].Credentials["non-matching-credential"]; ok {
		t.Fatal("non-matching-credential must not be in result")
	}
}

func TestDCQLQueryFilterMultipleMatchingCredentials(t *testing.T) {
	credentials := map[string]any{
		"cred-1": map[string]any{
			"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
			"type":              []any{"VerifiableCredential"},
			"credentialSubject": map[string]any{"country": "DE"},
		},
		"cred-2": map[string]any{
			"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
			"type":              []any{"VerifiableCredential"},
			"credentialSubject": map[string]any{"country": "FR"},
		},
		"cred-3": map[string]any{
			"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
			"type":              []any{"VerifiableCredential"},
			"credentialSubject": map[string]any{"country": "US"},
		},
	}
	query := DCQLQuery{Credentials: []CredentialQuery{{
		ID: "eu", Format: types.LDPVC, Meta: map[string]any{},
		Claims: []ClaimQuery{{Path: ClaimsPathPointer{"credentialSubject", "country"}, Values: []any{"DE", "FR"}}},
	}}}

	results, err := query.Filter(credentials)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 || len(results[0].Credentials) != 2 {
		t.Fatalf("expected two matching credentials, got %#v", results)
	}
	if _, ok := results[0].Credentials["cred-1"]; !ok {
		t.Fatal("expected cred-1 to match")
	}
	if _, ok := results[0].Credentials["cred-2"]; !ok {
		t.Fatal("expected cred-2 to match")
	}
	if _, ok := results[0].Credentials["cred-3"]; ok {
		t.Fatal("cred-3 must not match")
	}
}

func TestDCQLQueryFilterSkipsUnsupportedStoredCredential(t *testing.T) {
	credentials := map[string]any{
		"unsupported": 12345,
		"matching": map[string]any{
			"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
			"type":              []any{"VerifiableCredential"},
			"credentialSubject": map[string]any{"age": 42.0},
		},
	}
	query := DCQLQuery{Credentials: []CredentialQuery{{
		ID: "age", Format: types.LDPVC, Meta: map[string]any{},
		Claims: []ClaimQuery{{Path: ClaimsPathPointer{"credentialSubject", "age"}, Values: []any{42.0}}},
	}}}

	results, err := query.Filter(credentials)
	if err != nil {
		t.Fatalf("unsupported stored credential must not abort filtering: %v", err)
	}
	if len(results) != 1 || len(results[0].Credentials) != 1 {
		t.Fatalf("expected supported matching credential to survive, got %#v", results)
	}
	if _, ok := results[0].Credentials["matching"]; !ok {
		t.Fatal("expected matching credential in result")
	}
}

func TestDCQLValidateRejectsDuplicateCredentialQueryID(t *testing.T) {
	q := DCQLQuery{Credentials: []CredentialQuery{
		{ID: "pid", Format: types.LDPVC, Meta: map[string]any{}},
		{ID: "pid", Format: types.LDPVC, Meta: map[string]any{}},
	}}
	if err := q.Validate(); err == nil {
		t.Fatal("expected duplicate credential query id to fail")
	}
}

func TestDCQLValidateRejectsDuplicateClaimID(t *testing.T) {
	q := DCQLQuery{Credentials: []CredentialQuery{{
		ID: "pid", Format: types.LDPVC, Meta: map[string]any{},
		Claims: []ClaimQuery{
			{ID: "name", Path: ClaimsPathPointer{"credentialSubject", "given_name"}},
			{ID: "name", Path: ClaimsPathPointer{"credentialSubject", "family_name"}},
		},
	}}}
	if err := q.Validate(); err == nil {
		t.Fatal("expected duplicate claim id to fail")
	}
}
