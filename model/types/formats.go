package types

import (
	"encoding/json"
	"errors"
	"strings"

	go_sd_jwt "github.com/MichaelFraser99/go-sd-jwt"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/sirupsen/logrus"
)

type CredentialFormat string
type PresentationFormat string

const (
	SDJWT   CredentialFormat = "dc+sd-jwt"
	JWTVC   CredentialFormat = "jwt_vc_json"
	LDPVC   CredentialFormat = "ldp_vc"
	MSOMDOC CredentialFormat = "mso_mdoc"
	UNKNOWN CredentialFormat = "unknown"
)

const (
	SDJWTVP   PresentationFormat = "dc+sd-jwt"
	JWTVP     PresentationFormat = "jwt_vc_json"
	LDPVP     PresentationFormat = "ldp_vp"
	MSOMDOCVP PresentationFormat = "mso_mdoc"
)

type Credential struct {
	Format CredentialFormat
	Json   map[string]interface{}
}

func CheckFormat(credential interface{}) (*Credential, error) {

	c := Credential{
		Format: UNKNOWN,
		Json:   nil,
	}

	if credential == nil {
		return &c, errors.New("credential nil")
	}

	m, ok := credential.(map[string]interface{})

	if ok {
		if !looksLikeW3CObject(m) {
			return &c, errors.New("JSON object is not recognizable as a W3C Verifiable Credential")
		}
		c.Format = LDPVC
		c.Json = m
		return &c, nil
	} else {

		s, ok := credential.(string)

		if ok {

			var j map[string]interface{}

			err := json.Unmarshal([]byte(s), &j)

			if err == nil {
				if !looksLikeW3CObject(j) {
					return &c, errors.New("JSON object is not recognizable as a W3C Verifiable Credential")
				}
				c.Format = LDPVC
				c.Json = j
				return &c, nil
			}

			if strings.Contains(s, "~") {

				if s[len(s)-1] != '~' {
					s = s + "~"
				}

				t, err := go_sd_jwt.New(s)

				if err != nil {
					logrus.Error(err)
					logrus.Info(s)
					return &c, err
				}

				c.Json, err = t.GetDisclosedClaims()

				if err != nil {
					logrus.Error(err)
					logrus.Info(s)
					return &c, err
				}
				c.Format = SDJWT

			} else {

				tok, err := jwt.ParseInsecure([]byte(s))
				if err != nil {
					logrus.Error(err)
					logrus.Info(s)
					return &c, err
				}
				c.Json = tok.PrivateClaims()
				c.Format = JWTVC
			}

			return &c, nil
		}
	}

	return &c, errors.ErrUnsupported
}

func looksLikeW3CObject(m map[string]interface{}) bool {
	if _, ok := m["@context"]; !ok {
		return false
	}
	t, ok := m["type"]
	if !ok {
		return false
	}
	switch v := t.(type) {
	case string:
		return v == "VerifiableCredential" || v == "VerifiablePresentation"
	case []interface{}:
		for _, x := range v {
			if x == "VerifiableCredential" || x == "VerifiablePresentation" {
				return true
			}
		}
	case []string:
		for _, x := range v {
			if x == "VerifiableCredential" || x == "VerifiablePresentation" {
				return true
			}
		}
	}
	return false
}
