package presentation

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/types"
)

// ClaimsPathPointer is the OID4VP 1.0 claims path pointer representation.
// Each element MUST be a string, null, or a non-negative integer.
type ClaimsPathPointer []any

func (p ClaimsPathPointer) Validate() error {
	if len(p) == 0 {
		return errors.New("claims path pointer must not be empty")
	}
	for i, part := range p {
		switch v := part.(type) {
		case string, nil:
			// valid
		case int:
			if v < 0 {
				return fmt.Errorf("claims path pointer element %d must be non-negative", i)
			}
		case int32:
			if v < 0 {
				return fmt.Errorf("claims path pointer element %d must be non-negative", i)
			}
		case int64:
			if v < 0 {
				return fmt.Errorf("claims path pointer element %d must be non-negative", i)
			}
		case float64:
			if v < 0 || v != float64(int64(v)) {
				return fmt.Errorf("claims path pointer element %d must be a non-negative integer", i)
			}
		default:
			return fmt.Errorf("claims path pointer element %d has unsupported type %T", i, part)
		}
	}
	return nil
}

// ResolveJSON applies the OID4VP claims path pointer semantics for JSON based credentials.
func (p ClaimsPathPointer) ResolveJSON(root any) ([]any, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}

	selected := []any{root}
	for _, part := range p {
		next := make([]any, 0)
		for _, current := range selected {
			switch v := part.(type) {
			case string:
				obj, ok := current.(map[string]any)
				if !ok {
					return nil, fmt.Errorf("cannot select key %q from %T", v, current)
				}
				if value, exists := obj[v]; exists {
					next = append(next, value)
				}
			case nil:
				arr, ok := current.([]any)
				if !ok {
					return nil, fmt.Errorf("cannot select all array elements from %T", current)
				}
				next = append(next, arr...)
			default:
				index, err := pathIndex(v)
				if err != nil {
					return nil, err
				}
				arr, ok := current.([]any)
				if !ok {
					return nil, fmt.Errorf("cannot select array index from %T", current)
				}
				if index < len(arr) {
					next = append(next, arr[index])
				}
			}
		}
		if len(next) == 0 {
			return nil, errors.New("claims path pointer selected no values")
		}
		selected = next
	}
	return selected, nil
}

func pathIndex(v any) (int, error) {
	switch n := v.(type) {
	case int:
		return n, nil
	case int32:
		return int(n), nil
	case int64:
		return int(n), nil
	case float64:
		if n < 0 || n != float64(int64(n)) {
			return 0, fmt.Errorf("path index must be a non-negative integer")
		}
		return int(n), nil
	default:
		return 0, fmt.Errorf("unsupported path index type %T", v)
	}
}

type DCQLQuery struct {
	Credentials    []CredentialQuery    `json:"credentials"`
	CredentialSets []CredentialSetQuery `json:"credential_sets,omitempty"`
}

type CredentialQuery struct {
	ID                                string         `json:"id"`
	Format                            string         `json:"format"`
	Meta                              map[string]any `json:"meta,omitempty"`
	Claims                            []ClaimQuery   `json:"claims,omitempty"`
	ClaimSets                         [][]string     `json:"claim_sets,omitempty"`
	Multiple                          *bool          `json:"multiple,omitempty"`
	RequireCryptographicHolderBinding *bool          `json:"require_cryptographic_holder_binding,omitempty"`
}

type ClaimQuery struct {
	ID     string            `json:"id,omitempty"`
	Path   ClaimsPathPointer `json:"path"`
	Values []any             `json:"values,omitempty"`
}

type CredentialSetQuery struct {
	Options  [][]string `json:"options"`
	Required *bool      `json:"required,omitempty"`
	Purpose  any        `json:"purpose,omitempty"`
}

type DCQLFilterResult struct {
	QueryID     string
	Credentials []FilterResult
}

func (q *DCQLQuery) Validate() error {
	if q == nil || len(q.Credentials) == 0 {
		return errors.New("dcql_query must contain at least one credential query")
	}

	ids := make(map[string]struct{}, len(q.Credentials))
	for i := range q.Credentials {
		cq := &q.Credentials[i]
		if cq.ID == "" {
			return fmt.Errorf("credential query %d: id is required", i)
		}
		if _, exists := ids[cq.ID]; exists {
			return fmt.Errorf("credential query id %q is not unique", cq.ID)
		}
		ids[cq.ID] = struct{}{}
		if cq.Format == "" {
			return fmt.Errorf("credential query %q: format is required", cq.ID)
		}

		claimIDs := map[string]struct{}{}
		for j, claim := range cq.Claims {
			if err := claim.Path.Validate(); err != nil {
				return fmt.Errorf("credential query %q claim %d: %w", cq.ID, j, err)
			}
			if claim.ID != "" {
				if _, exists := claimIDs[claim.ID]; exists {
					return fmt.Errorf("credential query %q: claim id %q is not unique", cq.ID, claim.ID)
				}
				claimIDs[claim.ID] = struct{}{}
			}
		}
		for _, set := range cq.ClaimSets {
			if len(set) == 0 {
				return fmt.Errorf("credential query %q: claim_sets entries must not be empty", cq.ID)
			}
			for _, id := range set {
				if _, ok := claimIDs[id]; !ok {
					return fmt.Errorf("credential query %q: claim_sets references unknown claim id %q", cq.ID, id)
				}
			}
		}
	}

	for i, set := range q.CredentialSets {
		if len(set.Options) == 0 {
			return fmt.Errorf("credential_set %d: options must not be empty", i)
		}
		for _, option := range set.Options {
			if len(option) == 0 {
				return fmt.Errorf("credential_set %d: options entries must not be empty", i)
			}
			for _, id := range option {
				if _, ok := ids[id]; !ok {
					return fmt.Errorf("credential_set %d references unknown credential query id %q", i, id)
				}
			}
		}
	}
	return nil
}

// Filter is retained as a convenience adapter for the existing credential store.
// It uses OID4VP Claims Path Pointer semantics for JSON-based credentials.
func (q *DCQLQuery) Filter(credentials map[string]any) ([]FilterResult, error) {
	if err := q.Validate(); err != nil {
		return nil, err
	}

	temp := map[string]*FilterResult{}
	for key, raw := range credentials {
		credential, err := types.CheckFormat(raw)
		if err != nil {
			return nil, fmt.Errorf("unsupported credential %s: %w", key, err)
		}

		for i := range q.Credentials {
			cq := &q.Credentials[i]
			match, err := cq.evaluateCredentialQuery(credential, string(credential.Format))
			if err != nil {
				return nil, fmt.Errorf("credential query %q evaluation failed: %w", cq.ID, err)
			}
			if !match {
				continue
			}

			if temp[cq.ID] == nil {
				temp[cq.ID] = &FilterResult{
					Description: Description{Id: cq.ID, FormatType: string(credential.Format)},
					Credentials: map[string]CredentialResult{},
				}
			}
			temp[cq.ID].Credentials[key] = CredentialResult{Type: string(credential.Format), Data: raw}
		}
	}

	result := make([]FilterResult, 0, len(temp))
	for _, cq := range q.Credentials { // deterministic query order
		if fr := temp[cq.ID]; fr != nil {
			result = append(result, *fr)
		}
	}
	return result, nil
}

func (q *CredentialQuery) evaluateCredentialQuery(c *types.Credential, format string) (bool, error) {
	if q.Format != format || c.Format != types.CredentialFormat(q.Format) {
		return false, nil
	}
	if !matchMetadata(q.Meta, c.Json, q.Format) {
		return false, nil
	}

	if len(q.ClaimSets) > 0 {
		byID := make(map[string]ClaimQuery, len(q.Claims))
		for _, claim := range q.Claims {
			if claim.ID != "" {
				byID[claim.ID] = claim
			}
		}
		for _, set := range q.ClaimSets {
			setMatches := true
			for _, id := range set {
				claim, ok := byID[id]
				if !ok || !claimMatches(claim, c.Json) {
					setMatches = false
					break
				}
			}
			if setMatches {
				return true, nil
			}
		}
		return false, nil
	}

	for _, claim := range q.Claims {
		if !claimMatches(claim, c.Json) {
			return false, nil
		}
	}
	return true, nil
}

func claimMatches(claim ClaimQuery, document map[string]any) bool {
	values, err := claim.Path.ResolveJSON(document)
	if err != nil {
		return false
	}
	if len(claim.Values) == 0 {
		return len(values) > 0
	}
	for _, actual := range values {
		for _, allowed := range claim.Values {
			if valuesEqual(actual, allowed) {
				return true
			}
		}
	}
	return false
}

func valuesEqual(actual, expected any) bool {
	// JSON unmarshalling turns numbers into float64. Normalize through JSON to
	// preserve JSON value semantics across programmatically-built and decoded values.
	a, aErr := json.Marshal(actual)
	b, bErr := json.Marshal(expected)
	if aErr == nil && bErr == nil && string(a) == string(b) {
		return true
	}
	return reflect.DeepEqual(actual, expected)
}

func matchMetadata(meta map[string]any, claims map[string]any, format string) bool {
	for name, expected := range meta {
		switch name {
		case "vct_values":
			if format != string(types.SDJWT) {
				return false
			}
			actual, ok := claims["vct"]
			if !ok || !containsJSONValue(expected, actual) {
				return false
			}
		case "doctype_value":
			// mdoc parsing is intentionally delegated to a format adapter/service.
			// If a normalized credential exposes doctype, it can still be matched here.
			actual, ok := claims["doctype"]
			if !ok || !valuesEqual(actual, expected) {
				return false
			}
		default:
			// Extension metadata can be matched against normalized top-level metadata.
			actual, ok := claims[name]
			if !ok || !valuesEqual(actual, expected) {
				return false
			}
		}
	}
	return true
}

func containsJSONValue(container any, expected any) bool {
	switch values := container.(type) {
	case []any:
		for _, value := range values {
			if valuesEqual(value, expected) {
				return true
			}
		}
	case []string:
		for _, value := range values {
			if valuesEqual(value, expected) {
				return true
			}
		}
	default:
		return valuesEqual(container, expected)
	}
	return false
}
