package credential

import "github.com/eclipse-xfsc/oid4-vci-vp-library/model/presentation"

type CredentialStore interface {
	FindMatching(definition presentation.PresentationDefinition) ([]presentation.FilterResult, error)
}

type Credential struct {
	ID     string
	Format string
	Data   []byte // JWT or LD Credential
}
