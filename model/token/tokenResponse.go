// SPDX-FileCopyrightText: 2023 DTIT and TLABS.
// SPDX-License-Identifier: Apache-2.0

package token

import "github.com/eclipse-xfsc/oid4-vci-vp-library/model/oauth"

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`

	ExpiresIn uint `json:"expires_in,omitempty"`

	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`

	AuthorizationDetails []oauth.AuthorizationDetails `json:"authorization_details,omitempty"`
}
