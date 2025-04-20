// SPDX-FileCopyrightText: 2023 DTIT and TLABS.
// SPDX-License-Identifier: Apache-2.0
package presentation

type StateResponse struct {
	ID                 string             `json:"id,omitempty"`
	State              string             `json:"state,omitempty"`
	VerifiedAttributes VerifiedAttributes `json:"verified_attributes,omitempty"`
}

type VerifiedAttributes map[string]interface{}
