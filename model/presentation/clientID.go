package presentation

import (
	"fmt"
	"strings"
)

type ClientIdentifier struct {
	Prefix string
	Value  string
}

var standardClientIDPrefixes = map[string]struct{}{
	"pre-registered": {}, "redirect_uri": {}, "openid_federation": {}, "verifier_attestation": {},
	"decentralized_identifier": {}, "x509_san_dns": {}, "x509_hash": {},
}

func ParseClientIdentifier(v string) (ClientIdentifier, error) {
	if v == "" {
		return ClientIdentifier{}, fmt.Errorf("client identifier is empty")
	}
	i := strings.IndexByte(v, ':')
	if i < 0 {
		return ClientIdentifier{Prefix: "pre-registered", Value: v}, nil
	}
	p := v[:i]
	value := v[i+1:]
	if value == "" {
		return ClientIdentifier{}, fmt.Errorf("client identifier value is empty")
	}
	if _, ok := standardClientIDPrefixes[p]; !ok {
		return ClientIdentifier{}, fmt.Errorf("unsupported client identifier prefix %q", p)
	}
	return ClientIdentifier{Prefix: p, Value: value}, nil
}
func (c ClientIdentifier) RequiresSignedRequestObject() bool {
	switch c.Prefix {
	case "openid_federation", "decentralized_identifier", "verifier_attestation", "x509_san_dns", "x509_hash":
		return true
	default:
		return false
	}
}
