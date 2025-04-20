package presentation

import "github.com/eclipse-xfsc/oid4-vci-vp-library/model/types"

type RequestObject struct {
	Client_Id_Scheme          string                 `json:"client_id_scheme,omitempty"`
	PresentationDefinition    PresentationDefinition `json:"presentation_definition,omitempty"`
	PresentationDefinitionUri string                 `json:"presentation_definition_uri,omitempty"`
	Nonce                     string                 `json:"nonce"`
	ResponseType              types.ResponseType     `json:"response_type"`
	State                     string                 `json:"state,omitempty"`
	RedirectUri               string                 `json:"redirect_uri"`
	ClientID                  string                 `json:"client_id"`
	ResponseUri               string                 `json:"response_uri,omitempty"`
	ResponseMode              types.ResponseMode     `json:"response_mode"`
}
