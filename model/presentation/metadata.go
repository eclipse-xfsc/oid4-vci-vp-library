package presentation

import "fmt"

type FormatMetadata struct {
	AlgValues           []string `json:"alg_values,omitempty"`
	ProofTypeValues     []string `json:"proof_type_values,omitempty"`
	CryptosuiteValues   []string `json:"cryptosuite_values,omitempty"`
	IssuerAuthAlgValues []string `json:"issuerauth_alg_values,omitempty"`
	DeviceAuthAlgValues []string `json:"deviceauth_alg_values,omitempty"`
	SDJWTAlgValues      []string `json:"sd-jwt_alg_values,omitempty"`
	KBJWTAlgValues      []string `json:"kb-jwt_alg_values,omitempty"`
}
type JWKSet struct {
	Keys []map[string]any `json:"keys"`
}
type VerifierMetadata struct {
	JWKS                                *JWKSet                   `json:"jwks,omitempty"`
	EncryptedResponseEncValuesSupported []string                  `json:"encrypted_response_enc_values_supported,omitempty"`
	VPFormatsSupported                  map[string]FormatMetadata `json:"vp_formats_supported,omitempty"`
}
type WalletMetadata struct {
	JWKS                                      *JWKSet                   `json:"jwks,omitempty"`
	VPFormatsSupported                        map[string]FormatMetadata `json:"vp_formats_supported,omitempty"`
	ClientIDPrefixesSupported                 []string                  `json:"client_id_prefixes_supported,omitempty"`
	RequestObjectSigningAlgValuesSupported    []string                  `json:"request_object_signing_alg_values_supported,omitempty"`
	AuthorizationEncryptionAlgValuesSupported []string                  `json:"authorization_encryption_alg_values_supported,omitempty"`
	AuthorizationEncryptionEncValuesSupported []string                  `json:"authorization_encryption_enc_values_supported,omitempty"`
}

func (m *VerifierMetadata) Validate(responseMode string) error {
	if m == nil {
		return nil
	}
	if m.JWKS != nil {
		seen := map[string]struct{}{}
		for i, k := range m.JWKS.Keys {
			kid, _ := k["kid"].(string)
			if kid == "" {
				return fmt.Errorf("client_metadata.jwks.keys[%d].kid is required", i)
			}
			if _, ok := seen[kid]; ok {
				return fmt.Errorf("client_metadata JWK kid %q is not unique", kid)
			}
			seen[kid] = struct{}{}
		}
	}
	if len(m.EncryptedResponseEncValuesSupported) > 0 {
		if err := validateNonEmptyStrings("encrypted_response_enc_values_supported", m.EncryptedResponseEncValuesSupported); err != nil {
			return err
		}
	}
	for format, v := range m.VPFormatsSupported {
		if format == "" {
			return fmt.Errorf("vp_formats_supported contains an empty format identifier")
		}
		if err := v.Validate(format); err != nil {
			return err
		}
	}
	return nil
}
func (f FormatMetadata) Validate(format string) error {
	for name, v := range map[string][]string{"alg_values": f.AlgValues, "proof_type_values": f.ProofTypeValues, "cryptosuite_values": f.CryptosuiteValues, "issuerauth_alg_values": f.IssuerAuthAlgValues, "deviceauth_alg_values": f.DeviceAuthAlgValues, "sd-jwt_alg_values": f.SDJWTAlgValues, "kb-jwt_alg_values": f.KBJWTAlgValues} {
		if v != nil {
			if err := validateNonEmptyStrings(format+"."+name, v); err != nil {
				return err
			}
		}
	}
	return nil
}
func validateNonEmptyStrings(name string, v []string) error {
	if len(v) == 0 {
		return fmt.Errorf("%s must be non-empty when present", name)
	}
	for _, s := range v {
		if s == "" {
			return fmt.Errorf("%s must not contain empty values", name)
		}
	}
	return nil
}
