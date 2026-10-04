package presentation

// RequestObject models the protocol claims of an OID4VP 1.0 Request Object.
// Signature verification and key resolution are intentionally outside this model.
type RequestObject struct {
	AuthorizationRequest

	IssuedAt  int64  `json:"iat,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
	NotBefore int64  `json:"nbf,omitempty"`
	Issuer    string `json:"iss,omitempty"`
	Audience  any    `json:"aud,omitempty"`
	JWTID     string `json:"jti,omitempty"`
}
