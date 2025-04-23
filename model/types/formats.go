package types

import (
	"encoding/json"
	"errors"
	"strings"

	go_sd_jwt "github.com/SchulzeStTSI/go-sd-jwt"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/sirupsen/logrus"
)

type CredentialFormat string
type PresentationFormat string

const (
	SDJWT   CredentialFormat = "vc+sd-jwt"
	JWTVC   CredentialFormat = "jwt_vc"
	LDPVC   CredentialFormat = "ldp_vc"
	UNKNOWN CredentialFormat = "unknown"
)

const (
	LDPVP PresentationFormat = "ldp_vp"
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

	s, ok := credential.(string)

	if ok {
		var j map[string]interface{}

		err := json.Unmarshal([]byte(s), &j)

		if err == nil {
			c.Format = LDPVC
			c.Json = j
			logrus.Error(err)
			logrus.Info(s)
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

	return &c, errors.ErrUnsupported
}
