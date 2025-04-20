// SPDX-FileCopyrightText: 2023 DTIT and TLABS.
// SPDX-License-Identifier: Apache-2.0

package token

type TokenResponse struct {
	AccessToken     string `json:"access_token"`
	TokenType       string `json:"token_type"`
	ExpiresIn       uint   `json:"expires_in"`
	CNonce          string `json:"c_nonce"`
	CNonceExpiresIn uint   `json:"c_nonce_expires_in"`
}
