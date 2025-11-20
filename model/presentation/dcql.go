package presentation

import (
	"errors"
	"fmt"
	"strings"

	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/types"
	"github.com/oliveagle/jsonpath"
)

// ----------------------------
// DCQL STRUCTURES
// ----------------------------

type DCQLQuery struct {
	Credentials    []CredentialQuery    `json:"credentials"`               // MUST, non-empty
	CredentialSets []CredentialSetQuery `json:"credential_sets,omitempty"` // OPTIONAL
}

type CredentialQuery struct {
	ID                                string            `json:"id"`                                             // REQUIRED
	Format                            string            `json:"format"`                                         // REQUIRED
	Meta                              map[string]string `json:"meta,omitempty"`                                 // OPTIONAL – key/value filters on JSON fields
	Claims                            []ClaimQuery      `json:"claims,omitempty"`                               // OPTIONAL
	ClaimSets                         [][]string        `json:"claim_sets,omitempty"`                           // OPTIONAL
	Multiple                          *bool             `json:"multiple,omitempty"`                             // OPTIONAL, default false
	RequireCryptographicHolderBinding *bool             `json:"require_cryptographic_holder_binding,omitempty"` // OPTIONAL
}

type ClaimQuery struct {
	Path   []string `json:"path"`   // REQUIRED – e.g.: "$.credentialSubject.age"
	Values []string `json:"values"` // OPTIONAL – list of accepted values
}

type CredentialSetQuery struct {
	Options  [][]string  `json:"options"`            // REQUIRED
	Required *bool       `json:"required,omitempty"` // default true
	Purpose  interface{} `json:"purpose,omitempty"`
}

type DCQLFilterResult struct {
	QueryID     string
	Credentials []FilterResult
}

// ----------------------------
// MAIN FILTER ENTRYPOINT
// ----------------------------

func (q *DCQLQuery) Filter(credentials map[string]any) ([]FilterResult, error) {
	if len(q.Credentials) == 0 {
		return nil, errors.New("dcql_query must contain at least one credential query")
	}

	temp := map[string]*FilterResult{}

	for key, cred := range credentials {

		credType, err := types.CheckFormat(cred)
		if err != nil {
			return nil, fmt.Errorf("unsupported credential %s: %w", key, err)
		}

		for _, cq := range q.Credentials {

			match, err := cq.evaluateCredentialQuery(credType, string(credType.Format))
			if err != nil {
				return nil, fmt.Errorf("evaluation failed: %w", err)
			}
			if !match {
				continue
			}

			desc := Description{
				Id:         cq.ID,
				FormatType: string(credType.Format),
			}

			if temp[cq.ID] == nil {
				temp[cq.ID] = &FilterResult{
					Description: desc,
					Credentials: map[string]CredentialResult{},
				}
			}

			temp[cq.ID].Credentials[key] = CredentialResult{
				Type: string(credType.Format),
				Data: cred,
			}
		}
	}

	// convert map → array
	result := make([]FilterResult, 0, len(temp))
	for _, fr := range temp {
		result = append(result, *fr)
	}

	return result, nil
}

// ----------------------------
// CREDENTIAL QUERY EVALUATION
// ----------------------------

func (q *CredentialQuery) evaluateCredentialQuery(c *types.Credential, format string) (bool, error) {

	// --- 1. Format MUST match ---
	if q.Format != "" && q.Format != format {
		return false, nil
	}
	if c.Format != types.CredentialFormat(q.Format) {
		return false, nil
	}

	// --- 2. Meta checks (all MUST match) ---
	for field, val := range q.Meta {
		obj, err := jsonpath.JsonPathLookup(c.Json, field)
		if err != nil {
			return false, nil
		}
		str, ok := obj.(string)
		if !ok || str != val {
			return false, nil
		}
	}

	// --- 3. Claim checks ---
	// ClaimQueries = AND
	// Each ClaimQuery.Path = OR
	for _, claim := range q.Claims {

		claimMatched := false

		for _, path := range claim.Path {
			obj, err := jsonpath.JsonPathLookup(c.Json, path)
			if err != nil {
				continue
			}

			// No Values = presence check OK
			if len(claim.Values) == 0 {
				claimMatched = true
				break
			}

			// check if actual value ∈ accepted Values
			if matchClaimValue(obj, claim.Values) {
				claimMatched = true
				break
			}
		}

		// any ClaimQuery failing → whole query fails
		if !claimMatched {
			return false, nil
		}
	}

	return true, nil
}

// ----------------------------
// CLAIM VALUE CHECKING
// ----------------------------

func matchClaimValue(actual interface{}, values []string) bool {
	var actStr string

	switch v := actual.(type) {
	case string:
		actStr = v

	case float64:
		actStr = strings.TrimRight(strings.TrimRight(fmt.Sprintf("%f", v), "0"), ".")

	case int:
		actStr = fmt.Sprintf("%d", v)

	case int64:
		actStr = fmt.Sprintf("%d", v)

	case bool:
		if v {
			actStr = "true"
		} else {
			actStr = "false"
		}

	default:
		return false
	}

	for _, allowed := range values {
		if actStr == allowed {
			return true
		}
	}
	return false
}
