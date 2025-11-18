package presentation

type VerifierInfoEntry struct {
	Format        string      `json:"format"`                   // REQUIRED
	Data          interface{} `json:"data"`                     // REQUIRED (object or string)
	CredentialIDs []string    `json:"credential_ids,omitempty"` // OPTIONAL
}
