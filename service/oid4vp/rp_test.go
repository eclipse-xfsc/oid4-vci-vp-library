package oid4vp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/presentation"
	"github.com/stretchr/testify/assert"
)

// ---------------------------------------------------------------------------
// MOCK BACKEND
// ---------------------------------------------------------------------------

type MockBackend struct {
	MatchedCreds  []presentation.FilterResult
	VpToken       string
	VpTokenErr    error
	DirectPostErr error
}

func (mb *MockBackend) MatchCredentials(
	ctx context.Context,
	pd *presentation.PresentationDefinition,
	dcql *presentation.DCQLQuery,
) ([]presentation.FilterResult, error) {
	return mb.MatchedCreds, nil
}

func (mb *MockBackend) CreateVPToken(
	ctx context.Context,
	ar *presentation.AuthorizationRequest,
	reqObj map[string]interface{},
	selected []presentation.FilterResult,
) (string, *presentation.PresentationSubmission, error) {
	if mb.VpTokenErr != nil {
		return "", nil, mb.VpTokenErr
	}
	return mb.VpToken, &presentation.PresentationSubmission{
		Id: "presentation-submission",
	}, nil
}

func (mb *MockBackend) DirectPost(
	ctx context.Context,
	responseURI string,
	state string,
	vpToken string,
	presSub map[string]interface{},
) error {
	return mb.DirectPostErr
}

// ---------------------------------------------------------------------------
// HTTP MOCKING
// ---------------------------------------------------------------------------

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func newMockHTTPClient(t *testing.T, responder func(*http.Request) (*http.Response, error)) http.Client {
	return http.Client{
		Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			return responder(r)
		}),
	}
}

// ---------------------------------------------------------------------------
// HELPERS
// ---------------------------------------------------------------------------

// Fake PD (minimal)
func fakePD() *presentation.PresentationDefinition {
	return &presentation.PresentationDefinition{
		Description: presentation.Description{
			Id: "pd-test3",
		},
	}
}

// Fake RequestObject
func fakeRequestObject() map[string]interface{} {
	return map[string]interface{}{
		"presentation_definition": map[string]interface{}{
			"id": "pd-test",
		},
	}
}

// ---------------------------------------------------------------------------
// TESTS
// ---------------------------------------------------------------------------

func TestBeginFlow_Success(t *testing.T) {
	ctx := context.Background()

	backend := &MockBackend{
		MatchedCreds: []presentation.FilterResult{
			presentation.FilterResult{
				Description: presentation.Description{
					Id:         "cred-1",
					FormatType: "TestVC",
				},
			},
		},
	}

	// Mock HTTP-Client: jede GET-Anfrage liefert fakeRequestObject()
	mockClient := newMockHTTPClient(t, func(req *http.Request) (*http.Response, error) {
		assert.Equal(t, http.MethodGet, req.Method)
		body, _ := json.Marshal(fakeRequestObject())
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewReader(body)),
			Header:     make(http.Header),
		}, nil
	})

	rpService := NewRPService(backend, &mockClient)

	// Fake request_uri – muss eine gültige URL sein
	rawURL := "openid4vp://authorize?client_id=test&state=123&nonce=n1&request_uri=https%3A%2F%2Fexample.org%2Frequest"

	matches, ar, reqObj, err := rpService.BeginFlow(ctx, rawURL)
	assert.NoError(t, err)
	assert.NotNil(t, ar)
	assert.NotNil(t, reqObj)

	assert.Equal(t, "test", ar.ClientID)
	assert.Equal(t, "123", ar.State)

	assert.Len(t, matches, 1)
	assert.Equal(t, "cred-1", matches[0].Id)
}

func TestBeginFlow_NoCredentials(t *testing.T) {
	ctx := context.Background()

	backend := &MockBackend{
		MatchedCreds: []presentation.FilterResult{},
	}

	mockClient := newMockHTTPClient(t, func(req *http.Request) (*http.Response, error) {
		body, _ := json.Marshal(fakeRequestObject())
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewReader(body)),
			Header:     make(http.Header),
		}, nil
	})

	rpService := NewRPService(backend, &mockClient)

	rawURL := "openid4vp://authorize?request_uri=https%3A%2F%2Fexample.org%2Frequest"

	_, _, _, err := rpService.BeginFlow(ctx, rawURL)
	assert.Nil(t, err)
}

func TestContinueFlow_Success(t *testing.T) {
	ctx := context.Background()

	backend := &MockBackend{
		VpToken: "vp.jwt.mocked",
	}

	mockClient := newMockHTTPClient(t, func(req *http.Request) (*http.Response, error) {
		body, _ := json.Marshal(fakeRequestObject())
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewReader(body)),
			Header:     make(http.Header),
		}, nil
	})

	rpService := NewRPService(backend, &mockClient)

	ar := &presentation.AuthorizationRequest{
		ResponseURI: "https://verifier.example.org/callback",
		State:       "123",
	}

	reqObj := fakeRequestObject()

	selected := []presentation.FilterResult{
		{
			Description: presentation.Description{
				Id:         "cred-123",
				FormatType: "MyVC",
			},
		},
	}

	token, err := rpService.ContinueFlow(ctx, ar, reqObj, selected)

	assert.NoError(t, err)
	assert.Equal(t, "vp.jwt.mocked", token)
}

func TestContinueFlow_VPTokenCreationFails(t *testing.T) {
	ctx := context.Background()

	backend := &MockBackend{
		VpTokenErr: errors.New("vp creation failed"),
	}
	httpClient := http.Client{}
	rpService := NewRPService(backend, &httpClient)

	ar := &presentation.AuthorizationRequest{}
	reqObj := fakeRequestObject()

	_, err := rpService.ContinueFlow(ctx, ar, reqObj, []presentation.FilterResult{
		presentation.FilterResult{
			Description: presentation.Description{
				Id: "c1",
			},
		},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "vp creation failed")
}

func TestContinueFlow_DirectPostFails(t *testing.T) {
	ctx := context.Background()

	backend := &MockBackend{
		VpToken:       "vp.jwt",
		DirectPostErr: errors.New("post failed"),
	}
	httpClient := http.Client{}
	rpService := NewRPService(backend, &httpClient)

	ar := &presentation.AuthorizationRequest{
		ResponseURI: "https://verifier.example.org/callback",
		State:       "abc",
	}

	reqObj := fakeRequestObject()

	_, err := rpService.ContinueFlow(ctx, ar, reqObj, []presentation.FilterResult{
		presentation.FilterResult{
			Description: presentation.Description{
				Id: "c1",
			},
		},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "post failed")
}
