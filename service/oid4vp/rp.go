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

// WalletBackend contains application-specific wallet functionality.
// OID4VP protocol objects are kept in this library; credential storage and
// format-specific presentation creation remain behind this interface.
type WalletBackend interface {
	MatchCredentials(ctx context.Context, dcql *presentation.DCQLQuery) ([]presentation.FilterResult, error)

	CreateVPToken(ctx context.Context,
		ar *presentation.AuthorizationRequest,
		selected []presentation.FilterResult,
	) (presentation.VPToken, error)
}

// RelyingPartyBackend is retained as a source-compatible name for callers that
// already use NewRPService. New code should use WalletBackend.
type RelyingPartyBackend = WalletBackend

type RelyingPartyService struct {
	backend    WalletBackend
	httpClient *http.Client
}

type WalletService = RelyingPartyService

func NewRPService(backend WalletBackend, httpClient *http.Client) *RelyingPartyService {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &RelyingPartyService{backend: backend, httpClient: httpClient}
}

func NewWalletService(backend WalletBackend, httpClient *http.Client) *WalletService {
	return NewRPService(backend, httpClient)
}

// BeginFlow parses an OID4VP Authorization URL, resolves a JSON request object
// when request_uri is present, validates the final OID4VP request, and asks the
// wallet backend for matching credentials.
func (service *RelyingPartyService) BeginFlow(
	ctx context.Context,
	rawAuthorizationURL string,
) ([]presentation.FilterResult, *presentation.AuthorizationRequest, error) {
	ar, err := service.ParseAuthorizationURL(rawAuthorizationURL)
	if err != nil {
		return nil, nil, err
	}

	if ar.RequestURI != "" {
		resolved, err := service.FetchAuthorizationRequest(ctx, ar.RequestURI, ar.RequestURIMethod, ar.WalletNonce)
		if err != nil {
			return nil, nil, err
		}
		mergeAuthorizationRequest(ar, resolved)
	}

	if err := ar.Validate(); err != nil {
		return nil, nil, fmt.Errorf("invalid authorization request: %w", err)
	}
	if ar.DCQLQuery == nil {
		return nil, nil, fmt.Errorf("scope-based DCQL resolution is not implemented by this service")
	}

	matches, err := service.backend.MatchCredentials(ctx, ar.DCQLQuery)
	if err != nil {
		return nil, nil, err
	}
	return matches, ar, nil
}

func (service *RelyingPartyService) ContinueFlow(
	ctx context.Context,
	ar *presentation.AuthorizationRequest,
	selected []presentation.FilterResult,
) (presentation.VPToken, error) {
	if len(selected) == 0 {
		return nil, fmt.Errorf("no credentials selected")
	}
	if ar == nil || ar.DCQLQuery == nil {
		return nil, fmt.Errorf("dcql authorization request is required")
	}

	vpToken, err := service.backend.CreateVPToken(ctx, ar, selected)
	if err != nil {
		return nil, fmt.Errorf("vp token creation failed: %w", err)
	}
	if err := vpToken.ValidateAgainst(ar.DCQLQuery); err != nil {
		return nil, fmt.Errorf("invalid vp token: %w", err)
	}

	response := presentation.AuthorizationResponse{VPToken: vpToken, State: ar.State}
	if err := service.DirectPost(ctx, ar.ResponseURI, response); err != nil {
		return nil, fmt.Errorf("direct_post failed: %w", err)
	}
	return vpToken, nil
}

func (service *RelyingPartyService) DirectPost(
	ctx context.Context,
	responseURI string,
	response presentation.AuthorizationResponse,
) error {
	if responseURI == "" {
		return fmt.Errorf("response_uri missing")
	}
	vpToken, err := response.VPToken.JSONString()
	if err != nil {
		return fmt.Errorf("encode vp_token: %w", err)
	}

	form := url.Values{}
	form.Set("vp_token", vpToken)
	if response.State != "" {
		form.Set("state", response.State)
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
		body, _ := io.ReadAll(io.LimitReader(res.Body, 64*1024))
		return fmt.Errorf("http %d: %s", res.StatusCode, string(body))
	}
	return nil
}

func (service *RelyingPartyService) ParseAuthorizationURL(raw string) (*presentation.AuthorizationRequest, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	q := u.Query()

	ar := &presentation.AuthorizationRequest{
		ClientID:         q.Get("client_id"),
		ResponseType:     q.Get("response_type"),
		ResponseMode:     q.Get("response_mode"),
		State:            q.Get("state"),
		Nonce:            q.Get("nonce"),
		RequestURI:       q.Get("request_uri"),
		RequestURIMethod: q.Get("request_uri_method"),
		ResponseURI:      q.Get("response_uri"),
		RedirectURI:      q.Get("redirect_uri"),
		Scope:            q.Get("scope"),
		WalletNonce:      q.Get("wallet_nonce"),
		RawQuery:         q.Encode(),
	}
	if rawDCQL := q.Get("dcql_query"); rawDCQL != "" {
		var dcql presentation.DCQLQuery
		if err := json.Unmarshal([]byte(rawDCQL), &dcql); err != nil {
			return nil, fmt.Errorf("parse dcql_query: %w", err)
		}
		ar.DCQLQuery = &dcql
	}
	return ar, nil
}

// FetchAuthorizationRequest resolves a request_uri that returns a JSON encoded
// Authorization Request. Signed JWT Request Objects must be verified and decoded
// by the caller/integration layer before using this JSON helper.
func (service *RelyingPartyService) FetchAuthorizationRequest(
	ctx context.Context,
	uri string,
	method string,
	walletNonce string,
) (*presentation.AuthorizationRequest, error) {
	if method == "" {
		method = "get"
	}

	var req *http.Request
	var err error
	switch method {
	case "get":
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	case "post":
		form := url.Values{}
		if walletNonce != "" {
			form.Set("wallet_nonce", walletNonce)
		}
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, uri, bytes.NewBufferString(form.Encode()))
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	default:
		return nil, fmt.Errorf("unsupported request_uri_method %q", method)
	}
	if err != nil {
		return nil, err
	}

	res, err := service.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1024*1024))
	if err != nil {
		return nil, err
	}
	if res.StatusCode >= 300 {
		return nil, fmt.Errorf("http %d: %s", res.StatusCode, string(body))
	}

	var ar presentation.AuthorizationRequest
	if err := json.Unmarshal(body, &ar); err != nil {
		return nil, fmt.Errorf("request_uri response is not a JSON authorization request: %w", err)
	}
	return &ar, nil
}

func mergeAuthorizationRequest(target, source *presentation.AuthorizationRequest) {
	rawQuery := target.RawQuery
	requestURI := target.RequestURI
	requestURIMethod := target.RequestURIMethod
	walletNonce := target.WalletNonce
	*target = *source
	target.RawQuery = rawQuery
	if target.RequestURI == "" {
		target.RequestURI = requestURI
	}
	if target.RequestURIMethod == "" {
		target.RequestURIMethod = requestURIMethod
	}
	if target.WalletNonce == "" {
		target.WalletNonce = walletNonce
	}
}
