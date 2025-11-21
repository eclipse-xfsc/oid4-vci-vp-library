package oid4vp

import (
	"context"
	"fmt"
	"net/url"

	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/credential"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/presentation"
)

type BackendVerificationResult struct {
	Status  string
	Details map[string]interface{}
}

type VerifierBackend interface {
	///Params:
	///RequestDefinition: Defines the dcqlquery/presentation
	CreateAuthorizationRequest(ctx context.Context, requestDefinition string) (string, error)
	FetchSessionResult(ctx context.Context, state string) (*BackendVerificationResult, error)
	ForwardToVerifier(ctx context.Context, state string, vpToken string, rawBody string) error
}

type PolicyClient interface {
	VerifyVPToken(ctx context.Context, vpToken string) error
}

type VerifierService struct {
	backend           VerifierBackend
	presentationStore presentation.PresentationStore
	credStore         credential.CredentialStore
	policy            PolicyClient
	RequestBaseURL    string
}

func NewVerifierService(
	backend VerifierBackend,
	store presentation.PresentationStore,
	credStore credential.CredentialStore,
	policy PolicyClient,
	requestBaseURL string,
) *VerifierService {
	return &VerifierService{
		backend:           backend,
		presentationStore: store,
		credStore:         credStore,
		policy:            policy,
		RequestBaseURL:    requestBaseURL,
	}
}

func (s *VerifierService) Authorize(ctx context.Context, requestDefinition string) (*presentation.AuthorizeResult, error) {

	rawURL, err := s.backend.CreateAuthorizationRequest(ctx, requestDefinition)
	if err != nil {
		return nil, err
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}

	q := parsed.Query()
	state := q.Get("state")
	if state == "" {
		return nil, fmt.Errorf("authorization URL is missing 'state'")
	}

	ar := &presentation.AuthorizationRequest{
		ClientID:                  q.Get("client_id"),
		ResponseType:              q.Get("response_type"),
		ResponseMode:              q.Get("response_mode"),
		PresentationDefinitionURI: q.Get("presentation_definition_uri"),
		ResponseURI:               q.Get("response_uri"),
		State:                     state,
		Nonce:                     q.Get("nonce"),
		Scope:                     q.Get("scope"),
		RawQuery:                  parsed.RawQuery,
	}

	s.presentationStore.SaveRequest(state, ar)

	// create request_uri for deep-link mode
	var requestURI string
	var reqURIAuthURL string

	if s.RequestBaseURL != "" {
		requestURI = s.RequestBaseURL + url.PathEscape(state)

		u := &url.URL{Scheme: "openid4vp", Host: "authorize"}
		rq := url.Values{}
		rq.Set("request_uri", requestURI)
		rq.Set("client_id", ar.ClientID)
		rq.Set("response_mode", ar.ResponseMode)
		rq.Set("state", ar.State)
		u.RawQuery = rq.Encode()

		reqURIAuthURL = u.String()
	}

	return &presentation.AuthorizeResult{
		State:                  state,
		OpenID4VPURL:           rawURL,
		RequestURI:             requestURI,
		RequestURIAuthorizeURL: reqURIAuthURL,
	}, nil
}

func (s *VerifierService) GetRequestObject(state string) (*presentation.AuthorizationRequest, error) {
	ar, ok, err := s.presentationStore.GetRequest(state)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("unknown state")
	}

	return ar, nil
}

func (s *VerifierService) GetPresentationDefinition(state string) (*presentation.PresentationDefinition, error) {
	ar, ok, err := s.presentationStore.GetRequest(state)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("unknown state")
	}

	return ar.PresentationDefinition, nil
}

func (s *VerifierService) ProcessResponse(
	ctx context.Context,
	state string,
	vpToken string,
	rawBody string,
) (*presentation.VerificationResult, error) {

	// optional: run local policy BEFORE forwarding
	if s.policy != nil && vpToken != "" {
		if err := s.policy.VerifyVPToken(ctx, vpToken); err != nil {
			return nil, fmt.Errorf("policy rejected vp_token: %w", err)
		}
	}

	// If we have a VP token, forward to WaltID verifier-kit immediately
	if vpToken != "" {
		// Forward to WaltID verifier
		if err := s.backend.ForwardToVerifier(ctx, state, vpToken, rawBody); err != nil {
			// store failure result
			_ = s.presentationStore.SaveStatus(state, "forward_error", map[string]interface{}{
				"error": err.Error(),
			})
			return nil, err
		}

		// store raw vp only after forwarding succeeded
		_ = s.presentationStore.SaveVPToken(state, vpToken, []byte(rawBody))
		_ = s.presentationStore.SaveStatus(state, "received", nil)
	}

	// Poll backend for the final verification result
	res, err := s.backend.FetchSessionResult(ctx, state)
	if err != nil {
		return nil, err
	}

	// If backend not ready
	if res == nil {
		return &presentation.VerificationResult{
			State:  state,
			Status: "pending",
		}, nil
	}

	// Save final status
	_ = s.presentationStore.SaveStatus(state, res.Status, res.Details)

	return &presentation.VerificationResult{
		State:   state,
		Status:  res.Status,
		Details: res.Details,
	}, nil
}
