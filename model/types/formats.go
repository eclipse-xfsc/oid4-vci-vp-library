package types

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/sirupsen/logrus"
)

type CredentialFormat string

const (
	SDJWT   CredentialFormat = "dc+sd-jwt"
	JWTVC   CredentialFormat = "jwt_vc_json"
	LDPVC   CredentialFormat = "ldp_vc"
	MSOMDOC CredentialFormat = "mso_mdoc"
	UNKNOWN CredentialFormat = "unknown"
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

			if looksLikeSDJWT(s) {
				c.Json, err = normalizeSDJWTClaims(s)
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

func looksLikeSDJWT(s string) bool {
	parts := strings.Split(s, "~")
	return len(parts) > 1 && strings.Count(parts[0], ".") == 2
}

// normalizeSDJWTClaims creates the claim view needed for DCQL matching.
// It intentionally does not validate JWT signatures or the key-binding JWT;
// those belong to the presentation/verification flow. It does validate that
// every disclosed object claim is referenced by an _sd digest in the issuer
// payload before materializing it.
func normalizeSDJWTClaims(s string) (map[string]interface{}, error) {
	parts := strings.Split(s, "~")
	if len(parts) < 2 || strings.Count(parts[0], ".") != 2 {
		return nil, errors.New("invalid SD-JWT compact serialization")
	}

	claims, err := decodeJWTPayload(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decode SD-JWT issuer payload: %w", err)
	}

	alg, _ := claims["_sd_alg"].(string)
	if alg == "" {
		alg = "sha-256"
	}
	if !strings.EqualFold(alg, "sha-256") {
		return nil, fmt.Errorf("unsupported SD-JWT digest algorithm %q", alg)
	}

	components := parts[1:]
	for len(components) > 0 && components[len(components)-1] == "" {
		components = components[:len(components)-1]
	}

	// The final component may be a key-binding JWT. It is not a disclosure.
	if len(components) > 0 && strings.Count(components[len(components)-1], ".") == 2 {
		components = components[:len(components)-1]
	}

	for _, encoded := range components {
		if encoded == "" {
			continue
		}

		raw, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("decode SD-JWT disclosure: %w", err)
		}

		var disclosure []interface{}
		if err := json.Unmarshal(raw, &disclosure); err != nil {
			return nil, fmt.Errorf("decode SD-JWT disclosure JSON: %w", err)
		}
		if len(disclosure) != 3 {
			return nil, fmt.Errorf("unsupported SD-JWT disclosure with %d elements", len(disclosure))
		}

		name, ok := disclosure[1].(string)
		if !ok || name == "" {
			return nil, errors.New("SD-JWT object disclosure has no claim name")
		}

		digestBytes := sha256.Sum256([]byte(encoded))
		digest := base64.RawURLEncoding.EncodeToString(digestBytes[:])
		if !materializeDisclosure(claims, digest, name, disclosure[2]) {
			return nil, fmt.Errorf("no matching digest found for disclosure %q", name)
		}
	}

	return claims, nil
}

func decodeJWTPayload(compact string) (map[string]interface{}, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return nil, errors.New("JWT must contain three segments")
	}

	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil, err
	}
	return claims, nil
}

// materializeDisclosure finds the object containing the matching _sd digest
// and inserts the disclosed claim into that object.
func materializeDisclosure(v interface{}, digest, name string, value interface{}) bool {
	switch node := v.(type) {
	case map[string]interface{}:
		if sd, ok := node["_sd"].([]interface{}); ok {
			for _, candidate := range sd {
				if candidate == digest {
					node[name] = value
					return true
				}
			}
		}
		for _, child := range node {
			if materializeDisclosure(child, digest, name, value) {
				return true
			}
		}
	case []interface{}:
		for _, child := range node {
			if materializeDisclosure(child, digest, name, value) {
				return true
			}
		}
	}
	return false
}
