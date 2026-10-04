package presentation

import "encoding/json"

// VPToken is the OID4VP 1.0 VP Token object. Keys are DCQL Credential Query IDs;
// values contain one or more presentations matching that query.
type VPToken map[string][]json.RawMessage

func (v VPToken) ValidateAgainst(query *DCQLQuery) error {
	return validateVPTokenAgainstDCQL(v, query)
}

func (v VPToken) JSONString() (string, error) {
	encoded, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

type AuthorizationResponse struct {
	VPToken VPToken `json:"vp_token,omitempty"`
	State   string  `json:"state,omitempty"`

	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}
