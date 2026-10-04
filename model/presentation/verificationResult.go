package presentation

type VerificationResult struct {
	State   string                 `json:"state"`
	Status  string                 `json:"status"`
	Details map[string]interface{} `json:"details,omitempty"`
}
