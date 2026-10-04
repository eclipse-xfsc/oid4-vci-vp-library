package presentation

// ResponseParameters contains the OID4VP 1.0 response parameters used by this library.
type ResponseParameters struct {
	VPToken VPToken `json:"vp_token,omitempty"`
	State   string  `json:"state,omitempty"`

	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}
