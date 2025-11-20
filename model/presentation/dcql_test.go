package presentation

import (
	"testing"

	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/types"
)

// Hilfsfunktion zum Erzeugen eines Credentials für Tests.
func newTestCredential(format string, json map[string]interface{}) *types.Credential {
	return &types.Credential{
		Format: types.CredentialFormat(format),
		Json:   json,
	}
}

func boolPtr(b bool) *bool {
	return &b
}

func TestEvaluateCredentialQuery_FormatMismatch(t *testing.T) {
	cred := newTestCredential("ldp_vc", map[string]interface{}{
		"issuer": "did:example:123",
	})

	q := CredentialQuery{
		ID:     "cred-1",
		Format: "jwt_vc", // passt NICHT zu Credential
	}

	match, err := q.evaluateCredentialQuery(cred, string(cred.Format))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if match {
		t.Fatalf("expected format mismatch to be false, got true")
	}
}

func TestEvaluateCredentialQuery_MetaMatch(t *testing.T) {
	cred := newTestCredential("ldp_vc", map[string]interface{}{
		"issuer": "did:example:123",
	})

	q := CredentialQuery{
		ID:     "cred-issuer-match",
		Format: "ldp_vc",
		Meta: map[string]string{
			"$.issuer": "did:example:123",
		},
	}

	match, err := q.evaluateCredentialQuery(cred, string(cred.Format))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !match {
		t.Fatalf("expected meta to match, got false")
	}
}

func TestEvaluateCredentialQuery_MetaMismatch(t *testing.T) {
	cred := newTestCredential("ldp_vc", map[string]interface{}{
		"issuer": "did:example:123",
	})

	q := CredentialQuery{
		ID:     "cred-issuer-mismatch",
		Format: "ldp_vc",
		Meta: map[string]string{
			"$.issuer": "did:example:other",
		},
	}

	match, err := q.evaluateCredentialQuery(cred, string(cred.Format))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if match {
		t.Fatalf("expected meta mismatch to be false, got true")
	}
}

func TestEvaluateCredentialQuery_ClaimPathExists(t *testing.T) {
	cred := newTestCredential("ldp_vc", map[string]interface{}{
		"credentialSubject": map[string]interface{}{
			"age": 25,
		},
	})

	q := CredentialQuery{
		ID:     "cred-claims",
		Format: "ldp_vc",
		Claims: []ClaimQuery{
			{
				Path: []string{"$.credentialSubject.age"},
			},
		},
	}

	match, err := q.evaluateCredentialQuery(cred, string(cred.Format))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !match {
		t.Fatalf("expected claim path to exist and match, got false")
	}
}

func TestEvaluateCredentialQuery_ClaimPathMissing(t *testing.T) {
	cred := newTestCredential("ldp_vc", map[string]interface{}{
		"credentialSubject": map[string]interface{}{
			"name": "Alice",
		},
	})

	q := CredentialQuery{
		ID:     "cred-claims-missing",
		Format: "ldp_vc",
		Claims: []ClaimQuery{
			{
				Path: []string{"$.credentialSubject.age"},
			},
		},
	}

	match, err := q.evaluateCredentialQuery(cred, string(cred.Format))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if match {
		t.Fatalf("expected claim path lookup to fail and return false, got true")
	}
}

// --- Tests für DCQLQuery.Filter mit verschiedenen Kombinationen ---

func TestDCQLQueryFilter_SingleQuerySingleCredential(t *testing.T) {
	// Wir simulieren einen Credential Store mit einem Credential
	credJson := map[string]interface{}{
		"issuer": "did:example:123",
		"credentialSubject": map[string]interface{}{
			"age": 30,
		},
	}

	// HINWEIS:
	// Diese Tests gehen davon aus, dass types.CheckFormat(map[string]interface{})
	// ein Credential mit Format "ldp_vc" erkennt.
	credentials := map[string]any{
		"cred-1": credJson,
	}

	query := DCQLQuery{
		Credentials: []CredentialQuery{
			{
				ID:     "q1",
				Format: "ldp_vc",
				Meta: map[string]string{
					"$.issuer": "did:example:123",
				},
				Claims: []ClaimQuery{
					{Path: []string{"$.credentialSubject.age"}},
				},
				Multiple: boolPtr(false),
			},
		},
	}

	results, err := query.Filter(credentials)
	if err != nil {
		t.Fatalf("unexpected error in Filter: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 FilterResult, got %d", len(results))
	}

	fr := results[0]
	if fr.Description.Id != "q1" {
		t.Fatalf("expected Description.Id 'q1', got %s", fr.Description.Id)
	}
	if len(fr.Credentials) != 1 {
		t.Fatalf("expected 1 matched credential, got %d", len(fr.Credentials))
	}
	if _, ok := fr.Credentials["cred-1"]; !ok {
		t.Fatalf("expected credential key 'cred-1' in result")
	}
}

func TestDCQLQueryFilter_MultipleQueriesMultipleCredentials(t *testing.T) {
	credJson1 := map[string]interface{}{
		"issuer": "did:example:A",
		"credentialSubject": map[string]interface{}{
			"role": "employee",
		},
	}
	credJson2 := map[string]interface{}{
		"issuer": "did:example:B",
		"credentialSubject": map[string]interface{}{
			"role": "student",
		},
	}

	credentials := map[string]any{
		"cred-emp": credJson1,
		"cred-stu": credJson2,
	}

	query := DCQLQuery{
		Credentials: []CredentialQuery{
			{
				ID:     "q-employee",
				Format: "ldp_vc",
				Meta: map[string]string{
					"$.issuer": "did:example:A",
				},
				Claims: []ClaimQuery{
					{Path: []string{"$.credentialSubject.role"}, Values: []string{"employee"}},
				},
			},
			{
				ID:     "q-student",
				Format: "ldp_vc",
				Meta: map[string]string{
					"$.issuer": "did:example:B",
				},
				Claims: []ClaimQuery{
					{Path: []string{"$.credentialSubject.role"}, Values: []string{"student"}},
				},
			},
		},
	}

	results, err := query.Filter(credentials)
	if err != nil {
		t.Fatalf("unexpected error in Filter: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 FilterResult entries, got %d", len(results))
	}

	// Wir erwarten je ein Credential pro Query-ID
	byID := map[string]FilterResult{}
	for _, fr := range results {
		byID[fr.Description.Id] = fr
	}

	emp, ok := byID["q-employee"]
	if !ok {
		t.Fatalf("missing result for q-employee")
	}
	if len(emp.Credentials) != 1 {
		t.Fatalf("expected q-employee to have 1 credential, got %d", len(emp.Credentials))
	}

	stu, ok := byID["q-student"]
	if !ok {
		t.Fatalf("missing result for q-student")
	}
	if len(stu.Credentials) != 1 {
		t.Fatalf("expected q-student to have 1 credential, got %d", len(stu.Credentials))
	}
}

func TestDCQLQueryFilter_NoCredentialQueries(t *testing.T) {
	query := DCQLQuery{
		Credentials: nil,
	}

	_, err := query.Filter(map[string]any{})
	if err == nil {
		t.Fatalf("expected error when dcql_query has no credential queries")
	}
}

func TestDCQLQueryFilter_NoMatches(t *testing.T) {
	credJson := map[string]interface{}{
		"issuer": "did:example:123",
	}

	credentials := map[string]any{
		"cred-1": credJson,
	}

	query := DCQLQuery{
		Credentials: []CredentialQuery{
			{
				ID:     "q1",
				Format: "ldp_vc",
				Meta: map[string]string{
					"$.issuer": "did:example:OTHER",
				},
			},
		},
	}

	results, err := query.Filter(credentials)
	if err != nil {
		t.Fatalf("unexpected error in Filter: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("expected 0 results when no credentials match, got %d", len(results))
	}
}
