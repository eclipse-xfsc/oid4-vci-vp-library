package serivce

import (
	"context"
	"fmt"
	"net/url"

	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/presentation"
)

type BackendVerificationResult struct {
	Status  string
	Details map[string]interface{}
}

type Backend interface {
	CreateAuthorizationRequest(ctx context.Context, requestDefinition string) (string, error)
	FetchSessionResult(ctx context.Context, state string) (*BackendVerificationResult, error)
}

type Service struct {
	backend        Backend
	store          presentation.Store
	RequestBaseURL string
}

func NewService(backend Backend, store presentation.Store, requestBaseURL string) *Service {
	return &Service{
		backend:        backend,
		store:          store,
		RequestBaseURL: requestBaseURL,
	}
}

// 1) AUTHORIZE
func (s *Service) Authorize(ctx context.Context, requestDefinition string) (*presentation.AuthorizeResult, error) {
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
		RawQuery:                  parsed.RawQuery,
	}

	s.store.SaveRequest(state, ar)

	var requestURI, reqURIAuthURL string
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

// 2) REQUEST RETRIEVAL
func (s *Service) GetRequestObject(state string) (*presentation.AuthorizationRequest, error) {
	ar, ok, err := s.store.GetRequest(state)

	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, fmt.Errorf("unknown state")
	}
	return ar, nil
}

// 3) RESPONSE PROCESSING
func (s *Service) ProcessResponse(
	ctx context.Context,
	state string,
	vpToken string,
	rawBody string,
) (*presentation.VerificationResult, error) {

	// Even in backend mode, we should store inbound VP so we don't lose data
	if vpToken != "" {
		_ = s.store.SaveVPToken(state, vpToken, []byte(rawBody))
		_ = s.store.SaveStatus(state, "received", nil)
	}

	// Poll backend if available
	res, err := s.backend.FetchSessionResult(ctx, state)
	if err != nil {
		return nil, err
	}

	// Nothing available yet -> user should continue polling
	if res == nil {
		return &presentation.VerificationResult{
			State:  state,
			Status: "pending",
		}, nil
	}

	// Update store for later inspection
	_ = s.store.SaveStatus(state, res.Status, res.Details)

	return &presentation.VerificationResult{
		State:   state,
		Status:  res.Status,
		Details: res.Details,
	}, nil
}
