package oid4vp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/presentation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockBackend struct {
	MatchedCreds []presentation.FilterResult
	VPToken      presentation.VPToken
	VPTokenErr   error
}

func (mb *MockBackend) MatchCredentials(ctx context.Context, dcql *presentation.DCQLQuery) ([]presentation.FilterResult, error) {
	return mb.MatchedCreds, nil
}

func (mb *MockBackend) CreateVPToken(
	ctx context.Context,
	ar *presentation.AuthorizationRequest,
	selected []presentation.FilterResult,
) (presentation.VPToken, error) {
	if mb.VPTokenErr != nil {
		return nil, mb.VPTokenErr
	}
	return mb.VPToken, nil
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func newMockHTTPClient(responder func(*http.Request) (*http.Response, error)) http.Client {
	return http.Client{Transport: roundTripperFunc(responder)}
}

func finalRequest() presentation.AuthorizationRequest {
	return presentation.AuthorizationRequest{
		ClientID:     "x509_san_dns:verifier.example",
		ResponseType: "vp_token",
		ResponseMode: "direct_post",
		ResponseURI:  "https://verifier.example/response",
		Nonce:        "nonce-1",
		State:        "state-1",
		DCQLQuery:    &presentation.DCQLQuery{Credentials: []presentation.CredentialQuery{{ID: "pid", Format: "dc+sd-jwt"}}},
	}
}

func TestBeginFlowWithRequestURI(t *testing.T) {
	ctx := context.Background()
	backend := &MockBackend{MatchedCreds: []presentation.FilterResult{{Description: presentation.Description{Id: "pid"}}}}
	request := finalRequest()

	client := newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		assert.Equal(t, http.MethodGet, req.Method)
		body, _ := json.Marshal(request)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(body)), Header: make(http.Header)}, nil
	})
	service := NewWalletService(backend, &client)

	matches, ar, err := service.BeginFlow(ctx, "openid4vp://authorize?request_uri=https%3A%2F%2Fexample.org%2Frequest")
	require.NoError(t, err)
	require.NotNil(t, ar.DCQLQuery)
	assert.Equal(t, request.ClientID, ar.ClientID)
	assert.Len(t, matches, 1)
}

func TestBeginFlowInlineDCQL(t *testing.T) {
	backend := &MockBackend{}
	service := NewWalletService(backend, &http.Client{})
	query := `{"credentials":[{"id":"pid","format":"dc+sd-jwt"}]}`
	raw := "openid4vp://authorize?client_id=client&response_type=vp_token&response_mode=direct_post&response_uri=" +
		url.QueryEscape("https://verifier.example/response") + "&nonce=n&dcql_query=" + url.QueryEscape(query)

	_, ar, err := service.BeginFlow(context.Background(), raw)
	require.NoError(t, err)
	require.NotNil(t, ar.DCQLQuery)
	assert.Equal(t, "pid", ar.DCQLQuery.Credentials[0].ID)
}

func TestContinueFlowDirectPostUsesFinalVPToken(t *testing.T) {
	backend := &MockBackend{VPToken: presentation.VPToken{
		"pid": []json.RawMessage{json.RawMessage(`"sd-jwt-presentation"`)},
	}}
	client := newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		require.NoError(t, req.ParseForm())
		assert.Equal(t, `{"pid":["sd-jwt-presentation"]}`, req.Form.Get("vp_token"))
		assert.Equal(t, "state-1", req.Form.Get("state"))
		assert.Empty(t, req.Form.Get("presentation_submission"))
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(nil)), Header: make(http.Header)}, nil
	})
	service := NewWalletService(backend, &client)
	ar := finalRequest()

	token, err := service.ContinueFlow(context.Background(), &ar, []presentation.FilterResult{{Description: presentation.Description{Id: "pid"}}})
	require.NoError(t, err)
	assert.Len(t, token["pid"], 1)
}

func TestContinueFlowRejectsInvalidVPToken(t *testing.T) {
	backend := &MockBackend{VPToken: presentation.VPToken{
		"wrong": []json.RawMessage{json.RawMessage(`"presentation"`)},
	}}
	service := NewWalletService(backend, &http.Client{})
	ar := finalRequest()

	_, err := service.ContinueFlow(context.Background(), &ar, []presentation.FilterResult{{Description: presentation.Description{Id: "pid"}}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown credential query id")
}

func TestContinueFlowVPTokenCreationFails(t *testing.T) {
	backend := &MockBackend{VPTokenErr: errors.New("vp creation failed")}
	service := NewWalletService(backend, &http.Client{})
	ar := finalRequest()

	_, err := service.ContinueFlow(context.Background(), &ar, []presentation.FilterResult{{Description: presentation.Description{Id: "pid"}}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "vp creation failed")
}
