package presentation

import (
	"errors"
	"strings"
)

// AuthorizationRequest models the OID4VP 1.0 Authorization Request.
// Presentation Exchange fields deliberately do not live in this final-spec model.
type AuthorizationRequest struct {
	ClientID     string `json:"client_id"`
	ResponseType string `json:"response_type"`
	ResponseMode string `json:"response_mode,omitempty"`
	Nonce        string `json:"nonce"`
	State        string `json:"state,omitempty"`

	DCQLQuery *DCQLQuery `json:"dcql_query,omitempty"`
	Scope     string     `json:"scope,omitempty"`

	RedirectURI string `json:"redirect_uri,omitempty"`
	ResponseURI string `json:"response_uri,omitempty"`
	WalletNonce string `json:"wallet_nonce,omitempty"`

	RequestURI       string `json:"request_uri,omitempty"`
	RequestURIMethod string `json:"request_uri_method,omitempty"`

	TransactionData []string               `json:"transaction_data,omitempty"`
	VerifierInfo    []VerifierInfoEntry    `json:"verifier_info,omitempty"`
	ClientMetadata  map[string]interface{} `json:"client_metadata,omitempty"`

	RawQuery string `json:"-"`
}

func (r *AuthorizationRequest) Validate() error {
	if r.ClientID == "" {
		return errors.New("client_id is required")
	}
	if r.ResponseType == "" {
		return errors.New("response_type is required")
	}
	if !containsResponseType(r.ResponseType, "vp_token") && r.ResponseType != "code" {
		return errors.New("response_type must contain vp_token or be code")
	}
	if r.Nonce == "" {
		return errors.New("nonce is required")
	}
	if r.Scope == "" && r.DCQLQuery == nil {
		return errors.New("either scope or dcql_query is required")
	}
	if r.Scope != "" && r.DCQLQuery != nil {
		return errors.New("scope and dcql_query must not both be present")
	}
	if r.DCQLQuery != nil {
		if err := r.DCQLQuery.Validate(); err != nil {
			return err
		}
	}
	if (r.ResponseMode == "direct_post" || r.ResponseMode == "direct_post.jwt") && r.ResponseURI == "" {
		return errors.New("response_uri is required for direct_post response modes")
	}
	if r.RequestURIMethod != "" && r.RequestURIMethod != "get" && r.RequestURIMethod != "post" {
		return errors.New("request_uri_method must be get or post")
	}
	return nil
}

func containsResponseType(value, expected string) bool {
	for _, token := range strings.Fields(value) {
		if token == expected {
			return true
		}
	}
	return false
}
