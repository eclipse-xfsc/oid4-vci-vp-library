package presentation

import (
	"errors"
	"fmt"
)

type AuthorizationRequest struct {
	// === REQUIRED per OID4VP spec ===
	ClientID     string `json:"client_id"`     // MUST
	ResponseType string `json:"response_type"` // MUST ("vp_token" or "vp_token id_token")
	ResponseMode string `json:"response_mode"` // MUST
	Nonce        string `json:"nonce"`         // MUST

	// === Strongly RECOMMENDED / MUST in cross-device ===
	State string `json:"state,omitempty"` // REQUIRED for cross-device, RECOMMENDED otherwise

	// === Credential Query (one of MUST be present) ===
	DCQLQuery interface{} `json:"dcql_query,omitempty"` // MUST if no scope
	Scope     string      `json:"scope,omitempty"`      // MUST if no dcql_query

	// === Response delivery ===
	ResponseURI string `json:"response_uri,omitempty"` // REQUIRED if response_mode=direct_post
	WalletNonce string `json:"wallet_nonce,omitempty"` // OPTIONAL but RECOMMENDED by spec

	// === Request URI (request object mode) ===
	RequestURI       string `json:"request_uri,omitempty"`        // OPTIONAL
	RequestURIMethod string `json:"request_uri_method,omitempty"` // OPTIONAL ("get" or "post")

	// === Additional optional metadata ===
	TransactionData []string               `json:"transaction_data,omitempty"` // OPTIONAL
	VerifierInfo    []VerifierInfoEntry    `json:"verifier_info,omitempty"`    // OPTIONAL
	ClientMetadata  map[string]interface{} `json:"client_metadata,omitempty"`  // OPTIONAL

	// === Optional extension (used by some ecosystems) ===
	PresentationDefinitionURI string                  `json:"presentation_definition_uri,omitempty"` // OPTIONAL
	PresentationDefinition    *PresentationDefinition `json:"presentation_definition,omitempty"`     // OPTIONAL

	// === Internal: not exposed to wallets ===
	RawQuery string `json:"-"`
}

func (r *AuthorizationRequest) Validate() error {
	// === Absolute MUST fields =======
	if r.ClientID == "" {
		return errors.New("client_id is required (MUST)")
	}
	if r.ResponseType == "" {
		return errors.New("response_type is required (MUST)")
	}
	if r.ResponseMode == "" {
		return errors.New("response_mode is required (MUST)")
	}
	if r.Nonce == "" {
		return errors.New("nonce is required (MUST)")
	}

	// === Conditional MUST: dcql_query XOR scope ======
	if r.Scope == "" && r.DCQLQuery == nil && r.PresentationDefinitionURI == "" && r.PresentationDefinition == nil {
		return errors.New("either scope or dcql_query or presentation definition uri MUST be present")
	}

	if r.Scope != "" && r.DCQLQuery != nil {
		return errors.New("scope and dcql_query MUST NOT both be present")
	}

	if r.PresentationDefinitionURI != "" && r.PresentationDefinition != nil {
		return errors.New("presentation definition uri and presentationdefinition MUST NOT both be present")
	}

	if (r.PresentationDefinitionURI != "" || r.PresentationDefinition != nil) && r.Scope != "" {
		return errors.New("presentation definition and scope MUST NOT both be present")
	}

	if (r.PresentationDefinitionURI != "" || r.PresentationDefinition != nil) && r.DCQLQuery != nil {
		return errors.New("presentation definition and dcql query MUST NOT both be present")
	}

	// === Conditional MUST: response_uri only if response_mode=direct_post ===
	if r.ResponseMode == "direct_post" && r.ResponseURI == "" {
		return errors.New("response_uri is required when response_mode=direct_post (MUST)")
	}

	// === Strongly recommended: state for cross-device ===
	// (Not strictly MUST — but we warn strongly)
	if r.ResponseMode == "direct_post" && r.State == "" {
		// not an error per spec, so only warn in logs or return a soft error
		fmt.Println("warning: state is strongly recommended for cross-device flows")
	}

	// Everything OK
	return nil
}
