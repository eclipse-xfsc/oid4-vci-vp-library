package presentation

import "fmt"

func validateVPTokenAgainstDCQL(token VPToken, query *DCQLQuery) error {
	if query == nil {
		return fmt.Errorf("dcql query is required")
	}
	if err := query.Validate(); err != nil {
		return err
	}

	byID := make(map[string]CredentialQuery, len(query.Credentials))
	for _, cq := range query.Credentials {
		byID[cq.ID] = cq
	}
	for id, presentations := range token {
		cq, ok := byID[id]
		if !ok {
			return fmt.Errorf("vp_token contains unknown credential query id %q", id)
		}
		if len(presentations) == 0 {
			return fmt.Errorf("vp_token entry %q must contain at least one presentation", id)
		}
		multiple := cq.Multiple != nil && *cq.Multiple
		if !multiple && len(presentations) != 1 {
			return fmt.Errorf("vp_token entry %q must contain exactly one presentation when multiple is false or omitted", id)
		}
	}

	// Required credential sets define the combinations that have to be satisfied.
	if len(query.CredentialSets) == 0 {
		for _, cq := range query.Credentials {
			if len(token[cq.ID]) == 0 {
				return fmt.Errorf("vp_token is missing required credential query %q", cq.ID)
			}
		}
		return nil
	}

	for i, set := range query.CredentialSets {
		required := set.Required == nil || *set.Required
		if !required {
			continue
		}
		satisfied := false
		for _, option := range set.Options {
			optionSatisfied := true
			for _, id := range option {
				if len(token[id]) == 0 {
					optionSatisfied = false
					break
				}
			}
			if optionSatisfied {
				satisfied = true
				break
			}
		}
		if !satisfied {
			return fmt.Errorf("vp_token does not satisfy required credential_set %d", i)
		}
	}
	return nil
}
