package presentation

// VpResponse represents a parsed OID4VP 1.0 Authorization Response.
type VpResponse struct {
	State   string  `json:"state,omitempty"`
	VpToken VPToken `json:"vp_token,omitempty"`
	RawBody string  `json:"raw_body,omitempty"`

	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}
