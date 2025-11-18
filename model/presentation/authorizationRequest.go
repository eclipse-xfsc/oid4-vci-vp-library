package presentation

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
	PresentationDefinitionURI string `json:"presentation_definition_uri,omitempty"` // OPTIONAL

	// === Internal: not exposed to wallets ===
	RawQuery string `json:"-"`
}
