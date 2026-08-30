package credential

import "github.com/eclipse-xfsc/oid4-vci-vp-library/model/presentation"

type CredentialStore interface {
	// Deprecated: Presentation Exchange is not part of the OID4VP 1.0 DCQL core.
	FindMatchingByPresentationDefinition(definition presentation.PresentationDefinition) ([]presentation.FilterResult, error)
	FindMatchingDcqlQuery(definition presentation.DCQLQuery) ([]presentation.FilterResult, error)
}
