package presentation

import (
	"encoding/json"
	"testing"
)

func TestVPTokenWireFormatAndValidation(t *testing.T) {
	query := &DCQLQuery{Credentials: []CredentialQuery{{ID: "pid", Format: "dc+sd-jwt"}}}
	token := VPToken{"pid": []json.RawMessage{json.RawMessage(`"eyJhbGciOi..."`)}}

	if err := token.ValidateAgainst(query); err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	encoded, err := token.JSONString()
	if err != nil {
		t.Fatal(err)
	}
	if encoded != `{"pid":["eyJhbGciOi..."]}` {
		t.Fatalf("unexpected vp_token encoding: %s", encoded)
	}
}

func TestVPTokenRejectsMultipleWhenNotRequested(t *testing.T) {
	query := &DCQLQuery{Credentials: []CredentialQuery{{ID: "pid", Format: "dc+sd-jwt"}}}
	token := VPToken{"pid": []json.RawMessage{json.RawMessage(`"one"`), json.RawMessage(`"two"`)}}
	if err := token.ValidateAgainst(query); err == nil {
		t.Fatal("expected multiple presentations to be rejected")
	}
}

func TestVPTokenCredentialSets(t *testing.T) {
	query := &DCQLQuery{
		Credentials: []CredentialQuery{
			{ID: "pid", Format: "dc+sd-jwt"},
			{ID: "other_pid", Format: "dc+sd-jwt"},
		},
		CredentialSets: []CredentialSetQuery{{Options: [][]string{{"pid"}, {"other_pid"}}}},
	}
	token := VPToken{"other_pid": []json.RawMessage{json.RawMessage(`"presentation"`)}}
	if err := token.ValidateAgainst(query); err != nil {
		t.Fatalf("alternative credential set should be valid: %v", err)
	}
}
