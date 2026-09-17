package presentation

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

type AuthorizationRequest struct {
	ClientID         string              `json:"client_id"`
	ResponseType     string              `json:"response_type"`
	ResponseMode     string              `json:"response_mode,omitempty"`
	Nonce            string              `json:"nonce"`
	State            string              `json:"state,omitempty"`
	DCQLQuery        *DCQLQuery          `json:"dcql_query,omitempty"`
	Scope            string              `json:"scope,omitempty"`
	RedirectURI      string              `json:"redirect_uri,omitempty"`
	ResponseURI      string              `json:"response_uri,omitempty"`
	WalletNonce      string              `json:"wallet_nonce,omitempty"`
	Request          string              `json:"request,omitempty"`
	RequestURI       string              `json:"request_uri,omitempty"`
	RequestURIMethod string              `json:"request_uri_method,omitempty"`
	TransactionData  []string            `json:"transaction_data,omitempty"`
	VerifierInfo     []VerifierInfoEntry `json:"verifier_info,omitempty"`
	ClientMetadata   *VerifierMetadata   `json:"client_metadata,omitempty"`
	RawQuery         string              `json:"-"`
}

func (r *AuthorizationRequest) EffectiveResponseMode() string {
	if r.ResponseMode != "" {
		return r.ResponseMode
	}
	if containsResponseType(r.ResponseType, "vp_token") {
		return "fragment"
	}
	return ""
}

var oauthSafeValue = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)

func (r *AuthorizationRequest) Validate() error {
	if r.ClientID == "" {
		return errors.New("client_id is required")
	}
	if _, err := ParseClientIdentifier(r.ClientID); err != nil {
		return err
	}
	if r.ResponseType == "" {
		return errors.New("response_type is required")
	}
	if !containsResponseType(r.ResponseType, "vp_token") && r.ResponseType != "code" {
		return errors.New("response_type must contain vp_token or be code")
	}
	if containsResponseType(r.ResponseType, "vp_token") && r.Nonce == "" {
		return errors.New("nonce is required for vp_token")
	}
	if r.Nonce != "" && !oauthSafeValue.MatchString(r.Nonce) {
		return errors.New("nonce must contain only ASCII URL-safe characters")
	}
	if r.State != "" && !oauthSafeValue.MatchString(r.State) {
		return errors.New("state must contain only ASCII URL-safe characters")
	}
	if r.Scope == "" && r.DCQLQuery == nil {
		return errors.New("either scope or dcql_query is required")
	}
	if r.Scope != "" && r.DCQLQuery != nil {
		return errors.New("scope and dcql_query must not both be present")
	}
	if r.DCQLQuery != nil {
		if err := r.DCQLQuery.Validate(); err != nil {
			return err
		}
	}
	if r.DCQLQuery != nil {
		for _, cq := range r.DCQLQuery.Credentials {
			if cq.RequireCryptographicHolderBinding != nil && !*cq.RequireCryptographicHolderBinding && r.State == "" {
				return errors.New("state is required when a presentation without cryptographic holder binding is requested")
			}
		}
	}
	ids := map[string]struct{}{}
	if r.DCQLQuery != nil {
		for _, cq := range r.DCQLQuery.Credentials {
			ids[cq.ID] = struct{}{}
		}
	}
	for i, info := range r.VerifierInfo {
		if err := info.Validate(ids); err != nil {
			return fmt.Errorf("verifier_info[%d]: %w", i, err)
		}
	}
	mode := r.EffectiveResponseMode()
	if (mode == "direct_post" || mode == "direct_post.jwt") && r.ResponseURI == "" {
		return errors.New("response_uri is required for direct_post response modes")
	}
	if r.ResponseURI != "" && r.RedirectURI != "" {
		return errors.New("response_uri and redirect_uri must not both be present")
	}
	if r.RequestURIMethod != "" && r.RequestURI == "" {
		return errors.New("request_uri_method must not be present without request_uri")
	}
	if r.RequestURIMethod != "" && r.RequestURIMethod != "get" && r.RequestURIMethod != "post" {
		return errors.New("request_uri_method must be get or post")
	}
	if r.Request != "" && r.RequestURI != "" {
		return errors.New("request and request_uri must not both be present")
	}
	if len(r.TransactionData) > 0 {
		for i, v := range r.TransactionData {
			b, err := base64.RawURLEncoding.DecodeString(v)
			if err != nil {
				return fmt.Errorf("transaction_data[%d] must be base64url encoded: %w", i, err)
			}
			var obj map[string]any
			if json.Unmarshal(b, &obj) != nil || len(obj) == 0 {
				return fmt.Errorf("transaction_data[%d] must encode a non-empty JSON object", i)
			}
			typ, ok := obj["type"].(string)
			if !ok || typ == "" {
				return fmt.Errorf("transaction_data[%d] must contain a non-empty type", i)
			}
			idsRaw, ok := obj["credential_ids"].([]any)
			if !ok || len(idsRaw) == 0 {
				return fmt.Errorf("transaction_data[%d].credential_ids must be a non-empty array", i)
			}
			known := map[string]struct{}{}
			if r.DCQLQuery != nil {
				for _, cq := range r.DCQLQuery.Credentials {
					known[cq.ID] = struct{}{}
				}
			}
			for _, rawID := range idsRaw {
				id, ok := rawID.(string)
				if !ok || id == "" {
					return fmt.Errorf("transaction_data[%d].credential_ids must contain non-empty strings", i)
				}
				if _, ok := known[id]; !ok {
					return fmt.Errorf("transaction_data[%d] references unknown credential id %q", i, id)
				}
			}
		}
	}
	if err := r.ClientMetadata.Validate(mode); err != nil {
		return err
	}
	return nil
}
func containsResponseType(value, expected string) bool {
	for _, token := range strings.Fields(value) {
		if token == expected {
			return true
		}
	}
	return false
}
