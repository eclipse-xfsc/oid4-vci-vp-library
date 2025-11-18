package presentation

type VpResponse struct {
	State                  string                 `json:"state"`                             // corresponds to state param
	VpToken                string                 `json:"vp_token,omitempty"`                // MUST include vp_token when successful :contentReference[oaicite:16]{index=16}
	PresentationSubmission PresentationSubmission `json:"presentation_submission,omitempty"` // optional if following OID4VC/VP
	RawBody                string                 `json:"raw_body,omitempty"`
}
