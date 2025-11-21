package credential

import "github.com/eclipse-xfsc/oid4-vci-vp-library/model/presentation"

type CredentialStore interface {
	FindMatchingByPresentationDefinition(definition presentation.PresentationDefinition) ([]presentation.FilterResult, error)
	FindMatchingDcqlQuery(definition presentation.DCQLQuery) ([]presentation.FilterResult, error)
}
