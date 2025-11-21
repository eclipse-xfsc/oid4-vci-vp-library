package oid4vp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/presentation"
)

// Backend for wallet-like functionality (matching + vp creation only)
type RelyingPartyBackend interface {

	// Match credentials to PD or DCQL
	MatchCredentials(ctx context.Context,
		pd *presentation.PresentationDefinition,
		dcql *presentation.DCQLQuery,
	) ([]presentation.FilterResult, error)

	// Create VP Token & presentation submission
	CreateVPToken(ctx context.Context,
		ar *presentation.AuthorizationRequest,
		reqObj map[string]interface{},
		selected []presentation.FilterResult,
	) (vpToken string, presentationSubmission *presentation.PresentationSubmission, err error)
}

type RelyingPartyService struct {
	backend    RelyingPartyBackend
	httpClient *http.Client
}

func NewRPService(
	backend RelyingPartyBackend,
	httpClient *http.Client,
) *RelyingPartyService {
	return &RelyingPartyService{
		backend:    backend,
		httpClient: httpClient,
	}
}

// -----------------------------------------------------------------------------
// PHASE 1: BeginFlow
// -----------------------------------------------------------------------------
func (service *RelyingPartyService) BeginFlow(
	ctx context.Context,
	rawAuthorizationURL string,
) ([]presentation.FilterResult, *presentation.AuthorizationRequest, map[string]interface{}, error) {

	//--------------------------------------------------------------------
	// Parse Authorization URL
	//--------------------------------------------------------------------
	ar, err := service.ParseAuthorizationURL(rawAuthorizationURL)
	if err != nil {
		return nil, nil, nil, err
	}

	//--------------------------------------------------------------------
	// Load RequestObject
	//--------------------------------------------------------------------
	var reqObj map[string]interface{}

	switch {
	case ar.RequestURI != "":
		reqObj, err = service.FetchRequestObject(ctx, ar.RequestURI)
		if err != nil {
			return nil, nil, nil, err
		}

	case ar.PresentationDefinitionURI != "":
		pd, err := service.FetchPresentationDefinition(ctx, ar.PresentationDefinitionURI)
		if err != nil {
			return nil, nil, nil, err
		}
		reqObj = map[string]interface{}{"presentation_definition": pd}

	default:
		return nil, nil, nil, fmt.Errorf("no request_uri or pd_uri")
	}

	//--------------------------------------------------------------------
	// Extract PD/DCQL
	//--------------------------------------------------------------------
	if err := service.ResolvePresentationDefinition(ar, reqObj); err != nil {
		return nil, nil, nil, err
	}

	//--------------------------------------------------------------------
	// Credential Matching
	//--------------------------------------------------------------------
	matches, err := service.backend.MatchCredentials(ctx, ar.PresentationDefinition, ar.DCQLQuery)
	if err != nil {
		return nil, nil, nil, err
	}

	return matches, ar, reqObj, nil
}

// -----------------------------------------------------------------------------
// PHASE 2: ContinueFlow
// -----------------------------------------------------------------------------
func (service *RelyingPartyService) ContinueFlow(
	ctx context.Context,
	ar *presentation.AuthorizationRequest,
	reqObj map[string]interface{},
	selected []presentation.FilterResult,
) (string, error) {

	if len(selected) == 0 {
		return "", fmt.Errorf("no credentials selected")
	}

	vpToken, presSub, err := service.backend.CreateVPToken(ctx, ar, reqObj, selected)
	if err != nil {
		return "", fmt.Errorf("vp token creation failed: %w", err)
	}

	if err := service.DirectPost(ctx, ar.ResponseURI, ar.State, vpToken, presSub); err != nil {
		return "", fmt.Errorf("direct_post failed: %w", err)
	}

	return vpToken, nil
}

// -----------------------------------------------------------------------------
// DirectPost implemented INSIDE the service
// -----------------------------------------------------------------------------
func (service *RelyingPartyService) DirectPost(
	ctx context.Context,
	responseURI string,
	state string,
	vpToken string,
	presSub *presentation.PresentationSubmission,
) error {

	if responseURI == "" {
		return fmt.Errorf("response_uri missing")
	}

	form := url.Values{}
	form.Set("vp_token", vpToken)
	form.Set("state", state)

	if presSub != nil {
		bytes, _ := json.Marshal(presSub)
		form.Set("presentation_submission", string(bytes))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, responseURI, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := service.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode >= 300 {
		body, _ := io.ReadAll(res.Body)
		return fmt.Errorf("http %d: %s", res.StatusCode, string(body))
	}

	return nil
}

// -----------------------------------------------------------------------------
// Remaining helper functions unchanged
// -----------------------------------------------------------------------------
func (service *RelyingPartyService) ParseAuthorizationURL(raw string) (*presentation.AuthorizationRequest, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	q := u.Query()

	return &presentation.AuthorizationRequest{
		ClientID:                  q.Get("client_id"),
		State:                     q.Get("state"),
		Nonce:                     q.Get("nonce"),
		RequestURI:                q.Get("request_uri"),
		PresentationDefinitionURI: q.Get("presentation_definition_uri"),
		ResponseURI:               q.Get("response_uri"),
		Scope:                     q.Get("scope"),
		RawQuery:                  q.Encode(),
	}, nil
}

func (service *RelyingPartyService) FetchRequestObject(ctx context.Context, uri string) (map[string]interface{}, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, err
	}

	res, err := service.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	body, _ := io.ReadAll(res.Body)

	if res.StatusCode >= 300 {
		return nil, fmt.Errorf("http %d: %s", res.StatusCode, string(body))
	}

	var obj map[string]interface{}
	if err := json.Unmarshal(body, &obj); err != nil {
		return nil, err
	}
	return obj, nil
}

func (service *RelyingPartyService) FetchPresentationDefinition(
	ctx context.Context,
	uri string,
) (*presentation.PresentationDefinition, error) {

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, err
	}

	res, err := service.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	body, _ := io.ReadAll(res.Body)
	if res.StatusCode >= 300 {
		return nil, fmt.Errorf("http %d: %s", res.StatusCode, string(body))
	}

	var pd presentation.PresentationDefinition
	if err := json.Unmarshal(body, &pd); err != nil {
		return nil, err
	}
	return &pd, nil
}

func (service *RelyingPartyService) ResolvePresentationDefinition(
	ar *presentation.AuthorizationRequest,
	reqObj map[string]interface{},
) error {

	if pdRaw, ok := reqObj["presentation_definition"]; ok {
		buf, _ := json.Marshal(pdRaw)
		var pd presentation.PresentationDefinition
		if err := json.Unmarshal(buf, &pd); err != nil {
			return err
		}
		ar.PresentationDefinition = &pd
	}

	if dqRaw, ok := reqObj["dcql_query"]; ok {
		buf, _ := json.Marshal(dqRaw)
		var dq presentation.DCQLQuery
		if err := json.Unmarshal(buf, &dq); err != nil {
			return err
		}
		ar.DCQLQuery = &dq
	}

	if ar.PresentationDefinition == nil && ar.DCQLQuery == nil {
		return fmt.Errorf("no pd or dcql in request object")
	}

	return nil
}
