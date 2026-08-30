package credential

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/eclipse-xfsc/oid4-vci-vp-library/config"
	jwtext "github.com/eclipse-xfsc/ssi-jwt/v2"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

const (
	ProofTypeJWT         ProofVariant = "jwt"
	ProofTypeDIVP        ProofVariant = "di_vp"
	ProofTypeAttestation ProofVariant = "attestation"
)

type CredentialResponseEncryptionParameters struct {
	JWK json.RawMessage `json:"jwk"`
	Enc string          `json:"enc"`
	Zip string          `json:"zip,omitempty"`
}

func (p *CredentialResponseEncryptionParameters) Validate() error {
	if p == nil {
		return nil
	}

	if len(p.JWK) == 0 {
		return errors.New("credential response encryption jwk is required")
	}

	if p.Enc == "" {
		return errors.New("credential response encryption enc is required")
	}

	return nil
}

type CredentialRequest struct {
	// Exactly one of CredentialIdentifier or CredentialConfigurationID
	// MUST be present.
	CredentialIdentifier string `json:"credential_identifier,omitempty"`

	CredentialConfigurationID string `json:"credential_configuration_id,omitempty"`

	// Proofs is optional unless proof_types_supported is advertised
	// for the selected Credential Configuration.
	Proofs *CredentialProofs `json:"proofs,omitempty"`

	CredentialResponseEncryption *CredentialResponseEncryptionParameters `json:"credential_response_encryption,omitempty"`
}

type CredentialProofs struct {
	JWT []string `json:"jwt,omitempty"`

	// A di_vp proof is a W3C Verifiable Presentation object.
	DIVP []json.RawMessage `json:"di_vp,omitempty"`

	// The attestation proof type MUST contain exactly one JWT.
	Attestation []string `json:"attestation,omitempty"`
}

type JWTKeyProofClaims struct {
	Issuer string `json:"iss,omitempty"`

	Audience string `json:"aud"`

	// NumericDate, not string.
	IssuedAt int64 `json:"iat"`

	// Required only when the Credential Issuer has a Nonce Endpoint.
	Nonce string `json:"nonce,omitempty"`
}

func (request *CredentialRequest) CheckRequestValid(
	audience string,
	cNonce string,
	proofTypesSupported map[ProofVariant]ProofType,
) (bool, error) {

	if request == nil {
		return false, errors.New("credential request is nil")
	}

	hasCredentialIdentifier := request.CredentialIdentifier != ""
	hasCredentialConfigurationID := request.CredentialConfigurationID != ""

	if hasCredentialIdentifier == hasCredentialConfigurationID {
		return false, errors.New(
			"exactly one of credential_identifier or credential_configuration_id must be present",
		)
	}

	if len(proofTypesSupported) > 0 {
		if request.Proofs == nil {
			return false, errors.New(
				"proofs are required for the requested credential configuration",
			)
		}

		if err := request.Proofs.CheckProofs(
			audience,
			cNonce,
			proofTypesSupported,
		); err != nil {
			return false, err
		}
	}

	if request.CredentialResponseEncryption != nil {
		if err := request.CredentialResponseEncryption.Validate(); err != nil {
			return false, err
		}
	}

	return true, nil
}

func (proofs *CredentialProofs) CheckProofs(
	audience string,
	cNonce string,
	proofTypesSupported map[ProofVariant]ProofType,
) error {

	if proofs == nil {
		return errors.New("proofs are missing")
	}

	proofTypeCount := 0

	if len(proofs.JWT) > 0 {
		proofTypeCount++
	}

	if len(proofs.DIVP) > 0 {
		proofTypeCount++
	}

	if len(proofs.Attestation) > 0 {
		proofTypeCount++
	}

	if proofTypeCount == 0 {
		return errors.New("proofs must contain at least one proof")
	}

	if proofTypeCount != 1 {
		return errors.New("proofs must contain exactly one proof type")
	}

	switch {
	case len(proofs.JWT) > 0:
		if _, ok := proofTypesSupported[ProofTypeJWT]; !ok {
			return errors.New("jwt proof type is not supported")
		}

		for _, proof := range proofs.JWT {
			if err := checkJWTProof(
				proof,
				audience,
				cNonce,
			); err != nil {
				return err
			}
		}

		return nil

	case len(proofs.DIVP) > 0:
		if _, ok := proofTypesSupported[ProofTypeDIVP]; !ok {
			return errors.New("di_vp proof type is not supported")
		}

		return errors.New("di_vp proof validation is not implemented")

	case len(proofs.Attestation) > 0:
		if _, ok := proofTypesSupported[ProofTypeAttestation]; !ok {
			return errors.New("attestation proof type is not supported")
		}

		if len(proofs.Attestation) != 1 {
			return errors.New(
				"attestation proof type must contain exactly one attestation",
			)
		}

		return errors.New("attestation proof validation is not implemented")
	}

	return errors.New("unsupported proof type")
}

func checkJWTProof(
	proof string,
	audience string,
	cNonce string,
) error {

	if proof == "" {
		return errors.New("jwt proof must not be empty")
	}

	options := []jwt.ParseOption{
		jwt.WithAcceptableSkew(config.DefaultLeeway),
		jwt.WithRequiredClaim("iat"),
	}

	if audience != "" {
		options = append(
			options,
			jwt.WithRequiredClaim("aud"),
			jwt.WithAudience(audience),
		)
	}

	// nonce is only required if the Credential Issuer uses a Nonce Endpoint.
	//
	// At this layer cNonce == "" means nonce validation is disabled.
	if cNonce != "" {
		options = append(
			options,
			jwt.WithRequiredClaim("nonce"),
			jwt.WithClaimValue("nonce", cNonce),
		)
	}

	jToken, err := jwtext.Parse(proof, options...)
	if err != nil {
		return fmt.Errorf(
			"failed to verify JWT proof: %w",
			err,
		)
	}

	if jToken == nil {
		return errors.New("JWT proof is invalid")
	}

	if err := checkJWTProofClaims(jToken, audience, cNonce); err != nil {
		return err
	}

	return nil
}

func checkJWTProofClaims(
	token jwt.Token,
	audience string,
	cNonce string,
) error {

	issuedAt := token.IssuedAt()

	if issuedAt.IsZero() {
		return errors.New("JWT proof is missing iat")
	}

	if audience != "" {
		aud := token.Audience()

		if len(aud) == 0 {
			return errors.New("JWT proof is missing aud")
		}

		found := false

		for _, value := range aud {
			if value == audience {
				found = true
				break
			}
		}

		if !found {
			return errors.New("JWT proof audience does not match")
		}
	}

	if cNonce != "" {
		nonceValue, ok := token.Get("nonce")
		if !ok {
			return errors.New("JWT proof is missing nonce")
		}

		nonce, ok := nonceValue.(string)
		if !ok {
			return errors.New("JWT proof nonce must be a string")
		}

		if nonce != cNonce {
			return errors.New("JWT proof nonce does not match")
		}
	}

	return nil
}
