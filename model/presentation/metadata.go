package presentation

import "fmt"

type FormatMetadata struct {
	AlgValues           []string `json:"alg_values,omitempty"`
	ProofTypeValues     []string `json:"proof_type_values,omitempty"`
	CryptosuiteValues   []string `json:"cryptosuite_values,omitempty"`
	IssuerAuthAlgValues []any    `json:"issuerauth_alg_values,omitempty"`
	DeviceAuthAlgValues []any    `json:"deviceauth_alg_values,omitempty"`
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
			if kid != "" {
				if _, ok := seen[kid]; ok {
					return fmt.Errorf("client_metadata JWK kid %q is not unique", kid)
				}
				seen[kid] = struct{}{}
			}
			if responseMode == "direct_post.jwt" {
				alg, _ := k["alg"].(string)
				if alg == "" {
					return fmt.Errorf("client_metadata.jwks.keys[%d].alg is required for direct_post.jwt", i)
				}
			}
		}
	}
	if responseMode == "direct_post.jwt" && (m.JWKS == nil || len(m.JWKS.Keys) == 0) {
		return fmt.Errorf("client_metadata.jwks with at least one encryption key is required for direct_post.jwt")
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
	for name, v := range map[string][]string{"alg_values": f.AlgValues, "proof_type_values": f.ProofTypeValues, "cryptosuite_values": f.CryptosuiteValues, "sd-jwt_alg_values": f.SDJWTAlgValues, "kb-jwt_alg_values": f.KBJWTAlgValues} {
		if v != nil {
			if err := validateNonEmptyStrings(format+"."+name, v); err != nil {
				return err
			}
		}
	}
	for name, v := range map[string][]any{"issuerauth_alg_values": f.IssuerAuthAlgValues, "deviceauth_alg_values": f.DeviceAuthAlgValues} {
		if v != nil {
			if err := validateAlgorithmIdentifiers(format+"."+name, v); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateAlgorithmIdentifiers(name string, v []any) error {
	if len(v) == 0 {
		return fmt.Errorf("%s must be non-empty when present", name)
	}
	for _, value := range v {
		switch x := value.(type) {
		case string:
			if x == "" {
				return fmt.Errorf("%s must not contain empty values", name)
			}
		case float64, float32, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
			// JSON numbers are float64 after unmarshalling; integer Go values are accepted for construction.
		default:
			return fmt.Errorf("%s must contain only string or numeric algorithm identifiers", name)
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
