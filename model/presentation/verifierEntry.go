package presentation

import "fmt"

type VerifierInfoEntry struct {
	Format        string      `json:"format"`
	Data          interface{} `json:"data"`
	CredentialIDs []string    `json:"credential_ids,omitempty"`
}

func (v VerifierInfoEntry) Validate(credentialIDs map[string]struct{}) error {
	if v.Format == "" {
		return fmt.Errorf("verifier_info format is required")
	}
	if v.Data == nil {
		return fmt.Errorf("verifier_info data is required")
	}
	for _, id := range v.CredentialIDs {
		if _, ok := credentialIDs[id]; !ok {
			return fmt.Errorf("verifier_info references unknown credential query id %q", id)
		}
	}
	return nil
}
