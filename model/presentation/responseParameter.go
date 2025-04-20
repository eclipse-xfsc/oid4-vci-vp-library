package presentation

type ResponseParameters struct {
	VpToken                []byte                 `json:"vp_token"`
	PresentationSubmission PresentationSubmission `json:"presentation_submission"`
}
