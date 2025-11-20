package presentation

// PresentationStore defines state management for OID4VP cross-device flows.
//
// A PresentationStore implementation MUST be concurrency-safe.
type PresentationStore interface {
	// SaveRequest stores the authorization request parameters for a given state.
	SaveRequest(state string, ar *AuthorizationRequest) error

	// GetRequest returns the authorization request for a given state.
	// Returns (nil, false, nil) if state does not exist.
	GetRequest(state string) (*AuthorizationRequest, bool, error)

	// SaveVPToken stores a received vp_token for a given state
	// together with optional presentation_submission JSON.
	SaveVPToken(state string, vpToken string, presentationSubmission []byte) error

	// GetVPToken returns the stored vp_token and presentation_submission, if any.
	// Returns (empty values, false, nil) if nothing is stored for the state.
	GetVPToken(state string) (vpToken string, presentationSubmission []byte, exists bool, err error)

	// MarkStatus sets a verification status ("pending", "received", "success", "failed")
	// and optionally details from the verification backend.
	SaveStatus(state string, status string, details map[string]interface{}) error

	// GetStatus returns current verification status for polling.
	// Returns ("pending", nil, nil) if not yet known.
	GetStatus(state string) (status string, details map[string]interface{}, err error)
}
