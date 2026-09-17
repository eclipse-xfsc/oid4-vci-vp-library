package oid4vp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/presentation"
)

type WalletBackend interface {
	MatchCredentials(context.Context, *presentation.DCQLQuery) ([]presentation.FilterResult, error)
	CreateVPToken(context.Context, *presentation.AuthorizationRequest, []presentation.FilterResult) (presentation.VPToken, error)
}
type RelyingPartyBackend = WalletBackend

// RequestObjectVerifier MUST verify JAR/JWS/JWE according to RFC 9101 and the selected
// OID4VP Client Identifier Prefix. It returns only the verified request claims.
type RequestObjectVerifier interface {
	VerifyRequestObject(ctx context.Context, compact string, expectedClientID string, walletNonce string) (*presentation.AuthorizationRequest, error)
}

// ResponseEncryptor creates the unsigned encrypted JWT required by OID4VP direct_post.jwt.
type ResponseEncryptor interface {
	EncryptAuthorizationResponse(ctx context.Context, response presentation.AuthorizationResponse, metadata *presentation.VerifierMetadata) (string, error)
}

type RelyingPartyService struct {
	backend           WalletBackend
	httpClient        *http.Client
	requestVerifier   RequestObjectVerifier
	responseEncryptor ResponseEncryptor
	walletMetadata    *presentation.WalletMetadata
}
type WalletService = RelyingPartyService

func NewRPService(backend WalletBackend, client *http.Client) *RelyingPartyService {
	if client == nil {
		client = http.DefaultClient
	}
	return &RelyingPartyService{backend: backend, httpClient: client}
}
func NewWalletService(backend WalletBackend, client *http.Client) *WalletService {
	return NewRPService(backend, client)
}
func (s *RelyingPartyService) WithRequestObjectVerifier(v RequestObjectVerifier) *RelyingPartyService {
	s.requestVerifier = v
	return s
}
func (s *RelyingPartyService) WithResponseEncryptor(v ResponseEncryptor) *RelyingPartyService {
	s.responseEncryptor = v
	return s
}
func (s *RelyingPartyService) WithWalletMetadata(v *presentation.WalletMetadata) *RelyingPartyService {
	s.walletMetadata = v
	return s
}

func (s *RelyingPartyService) BeginFlow(ctx context.Context, raw string) ([]presentation.FilterResult, *presentation.AuthorizationRequest, error) {
	outer, err := s.ParseAuthorizationURL(raw)
	if err != nil {
		return nil, nil, err
	}
	ar := outer
	clientID, parseErr := presentation.ParseClientIdentifier(outer.ClientID)
	if parseErr != nil {
		return nil, nil, parseErr
	}
	if clientID.RequiresSignedRequestObject() && outer.Request == "" && outer.RequestURI == "" {
		return nil, nil, fmt.Errorf("client identifier prefix %q requires a signed Request Object", clientID.Prefix)
	}
	if outer.Request != "" || outer.RequestURI != "" {
		if outer.RequestURI != "" && outer.RequestURIMethod == "post" && outer.WalletNonce == "" {
			b := make([]byte, 16)
			if _, err := rand.Read(b); err != nil {
				return nil, nil, fmt.Errorf("generate wallet_nonce: %w", err)
			}
			outer.WalletNonce = base64.RawURLEncoding.EncodeToString(b)
		}
		if s.requestVerifier == nil {
			return nil, nil, fmt.Errorf("signed request object requires a RequestObjectVerifier")
		}
		compact := outer.Request
		if outer.RequestURI != "" {
			compact, err = s.FetchRequestObject(ctx, outer.RequestURI, outer.RequestURIMethod, outer.WalletNonce)
			if err != nil {
				return nil, nil, err
			}
		}
		verified, err := s.requestVerifier.VerifyRequestObject(ctx, compact, outer.ClientID, outer.WalletNonce)
		if err != nil {
			return nil, nil, fmt.Errorf("verify request object: %w", err)
		}
		if verified.ClientID != outer.ClientID {
			return nil, nil, fmt.Errorf("request object client_id does not match outer client_id")
		}
		// RFC 9101/OID4VP: only parameters from the verified Request Object are authoritative.
		verified.RawQuery = outer.RawQuery
		ar = verified
	}
	if err := ar.Validate(); err != nil {
		return nil, nil, fmt.Errorf("invalid authorization request: %w", err)
	}
	if ar.DCQLQuery == nil {
		return nil, nil, fmt.Errorf("scope-based DCQL resolution is not implemented by this service")
	}
	matches, err := s.backend.MatchCredentials(ctx, ar.DCQLQuery)
	if err != nil {
		return nil, nil, err
	}
	return matches, ar, nil
}

func (s *RelyingPartyService) ContinueFlow(ctx context.Context, ar *presentation.AuthorizationRequest, selected []presentation.FilterResult) (presentation.VPToken, error) {
	if len(selected) == 0 {
		return nil, fmt.Errorf("no credentials selected")
	}
	if ar == nil || ar.DCQLQuery == nil {
		return nil, fmt.Errorf("dcql authorization request is required")
	}
	token, err := s.backend.CreateVPToken(ctx, ar, selected)
	if err != nil {
		return nil, fmt.Errorf("vp token creation failed: %w", err)
	}
	if err = token.ValidateAgainst(ar.DCQLQuery); err != nil {
		return nil, fmt.Errorf("invalid vp token: %w", err)
	}
	response := presentation.AuthorizationResponse{VPToken: token, State: ar.State}
	switch ar.EffectiveResponseMode() {
	case "direct_post":
		_, err = s.DirectPost(ctx, ar.ResponseURI, response)
	case "direct_post.jwt":
		if s.responseEncryptor == nil {
			return nil, fmt.Errorf("direct_post.jwt requires a ResponseEncryptor")
		}
		var compact string
		compact, err = s.responseEncryptor.EncryptAuthorizationResponse(ctx, response, ar.ClientMetadata)
		if err == nil {
			_, err = s.DirectPostJWT(ctx, ar.ResponseURI, compact)
		}
	case "fragment":
		return token, nil // caller owns the browser/front-channel redirect
	default:
		return nil, fmt.Errorf("unsupported response_mode %q", ar.EffectiveResponseMode())
	}
	if err != nil {
		return nil, err
	}
	return token, nil
}

type DirectPostResponse struct {
	RedirectURI string `json:"redirect_uri,omitempty"`
}

func (s *RelyingPartyService) DirectPost(ctx context.Context, uri string, response presentation.AuthorizationResponse) (*DirectPostResponse, error) {
	vp, err := response.VPToken.JSONString()
	if err != nil {
		return nil, fmt.Errorf("encode vp_token: %w", err)
	}
	form := url.Values{"vp_token": {vp}}
	if response.State != "" {
		form.Set("state", response.State)
	}
	return s.postResponse(ctx, uri, form)
}
func (s *RelyingPartyService) DirectPostJWT(ctx context.Context, uri, compact string) (*DirectPostResponse, error) {
	if compact == "" {
		return nil, fmt.Errorf("encrypted response is empty")
	}
	return s.postResponse(ctx, uri, url.Values{"response": {compact}})
}
func (s *RelyingPartyService) postResponse(ctx context.Context, uri string, form url.Values) (*DirectPostResponse, error) {
	if uri == "" {
		return nil, fmt.Errorf("response_uri missing")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 64*1024))
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("response endpoint must return HTTP 200, got %d: %s", res.StatusCode, string(body))
	}
	out := &DirectPostResponse{}
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, fmt.Errorf("response endpoint must return a JSON object")
	}
	{
		if ct := res.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, "application/json") {
			return nil, fmt.Errorf("response endpoint must return application/json")
		}
		if err := json.Unmarshal(body, out); err != nil {
			return nil, fmt.Errorf("invalid response endpoint JSON: %w", err)
		}
	}
	return out, nil
}

func (s *RelyingPartyService) ParseAuthorizationURL(raw string) (*presentation.AuthorizationRequest, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	ar := &presentation.AuthorizationRequest{ClientID: q.Get("client_id"), ResponseType: q.Get("response_type"), ResponseMode: q.Get("response_mode"), State: q.Get("state"), Nonce: q.Get("nonce"), Request: q.Get("request"), RequestURI: q.Get("request_uri"), RequestURIMethod: q.Get("request_uri_method"), ResponseURI: q.Get("response_uri"), RedirectURI: q.Get("redirect_uri"), Scope: q.Get("scope"), RawQuery: q.Encode()}
	if rawDCQL := q.Get("dcql_query"); rawDCQL != "" {
		var d presentation.DCQLQuery
		if err := json.Unmarshal([]byte(rawDCQL), &d); err != nil {
			return nil, fmt.Errorf("parse dcql_query: %w", err)
		}
		ar.DCQLQuery = &d
	}
	if rawMeta := q.Get("client_metadata"); rawMeta != "" {
		var m presentation.VerifierMetadata
		if err := json.Unmarshal([]byte(rawMeta), &m); err != nil {
			return nil, fmt.Errorf("parse client_metadata: %w", err)
		}
		ar.ClientMetadata = &m
	}
	if values, ok := q["transaction_data"]; ok {
		ar.TransactionData = append([]string(nil), values...)
	}
	return ar, nil
}

func (s *RelyingPartyService) FetchRequestObject(ctx context.Context, uri, method, walletNonce string) (string, error) {
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
		if s.walletMetadata != nil {
			b, e := json.Marshal(s.walletMetadata)
			if e != nil {
				return "", e
			}
			form.Set("wallet_metadata", string(b))
		}
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, uri, bytes.NewBufferString(form.Encode()))
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Accept", "application/oauth-authz-req+jwt")
		}
	default:
		return "", fmt.Errorf("unsupported request_uri_method %q", method)
	}
	if err != nil {
		return "", err
	}
	res, err := s.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1024*1024))
	if err != nil {
		return "", err
	}
	if res.StatusCode >= 300 {
		return "", fmt.Errorf("http %d: %s", res.StatusCode, string(body))
	}
	if ct := res.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, "application/oauth-authz-req+jwt") {
		return "", fmt.Errorf("request_uri response content type must be application/oauth-authz-req+jwt")
	}
	return strings.TrimSpace(string(body)), nil
}

// FetchAuthorizationRequest is retained for source compatibility, but requires a configured verifier.
func (s *RelyingPartyService) FetchAuthorizationRequest(ctx context.Context, uri, method, walletNonce string) (*presentation.AuthorizationRequest, error) {
	if s.requestVerifier == nil {
		return nil, fmt.Errorf("signed request object requires a RequestObjectVerifier")
	}
	raw, err := s.FetchRequestObject(ctx, uri, method, walletNonce)
	if err != nil {
		return nil, err
	}
	return s.requestVerifier.VerifyRequestObject(ctx, raw, "", walletNonce)
}
