package credential

import "github.com/eclipse-xfsc/oid4-vci-vp-library/model/presentation"

type CredentialStore interface {
	FindMatchingDcqlQuery(definition presentation.DCQLQuery) ([]presentation.FilterResult, error)
}
