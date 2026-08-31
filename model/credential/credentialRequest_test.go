package credential

import (
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

const jwkPrivKey = `{
    "p": "8d7JP9pnscGzfP_CLulPnoqaVwt25u2JxU-3UFtdix9QB1_r9Fhiu5CN2KRSmEifAt6nIGAFPPQBe3S3mtQbrs2r3yPpLdnFOLiuExbztTzLWur-EOCo9XZ2CDxGgtXxFLajc-5JZIt8FLqpWVwDforNlYnHRm9EvSPlOVqBNi0",
    "kty": "RSA",
    "q": "w8luzHLQwevYjzuQ2Ou6FXSaRiDqdcP4XwUrOl4FrLfJGaeQRBXlD5pVk3gM_yjnBr6gn-P4kYTf1f77tHFBMqNAxpSta7FVagCzDqNFEiBbQmK4mOrysxN_Uo8S7fEVhR8V3RRntNEVwoMv_y5lNmrv2KwciflDTW5HOcD5Rh8",
    "d": "KImJz0oB4-UHhTfq2_48zwaZBnDghYKNB94UaDfe6SW_R_ZBF8niYNVCfrkYDurPsE3wqx3_YFq2T4XRr2_UwGUvabhQktxFNa7CTG0P-DPO4Z4WyyiFo8KXg53QrmUKQ9ZyJy9U-ZGUuxOZplGZWxHamg28W87cmwNSfc9-wdqqGx32HtcGs817DZ8aJEd5EBzHY0IL9TZZ-BENvb0oaKvX-BCYAC4WYkY92c77ZgsYInFCmsLo_3Rdw5pXNf32cmDX0M5l7t3rj3JOcvH4k576C3t7L8S1mIEnR54rzkRKw-NsX6CAWnbnhCUHqQLB7mBZcHQIlyDpDL1UyrmeEQ",
    "e": "AQAB",
    "use": "sig",
    "qi": "WBLrSY-IlMYpNQfrBbOqlzKka5QztE-pAGDUS7d4-y3Mm83K4_XGnI6Vqtvfttq9iYi5-shukTu1nDbzpI_FQI1FjB2_NJq7tt2HUg4RouQ9XmKQ8_Lv4fYv0PeMkZYKLDJRNbgsHFFyfqPIhK75_XogfssDjw5Xyshq3ylBS4w",
    "dp": "pVtfkTT68Y7w7ANauYGuekBd9iaTWpuJNgki1WAxWrzElNYiVYHbtknEgBkPkqcLdwXLkpmy2xIitUl9gO-EIYTg_QPrFfqtF_NCpzBo2z499OF1YwqE2JPtbAHxXt9vG28l3ktJh-DIqs9Wmg4LIYc5uANi5qeJghm5S_WxIt0",
    "alg": "PS256",
    "dq": "G3IKUSirMPQByJpeBLqOvGE7GyeUFmwhThioZac2fm7JBwqhQ5oaISTOaDzE_aPbNuvUEnXfq26H_jSfTj0uGY4fD3daFCWoxpJQh3XFwfO9N0IlhHIzEX1jNMyPp8FK9f1UkEhC_Wrt9PV07f2v_H_jHWmLGqBRmfIik-sERps",
    "n": "uPsD5or7uGVyy9WmTc6amWzpGIZzsKCceUOh2slnptD8W8od1unUMws3uFZAGSYDaBceSQ7Wy5i8IJYJAY9Zu_GYGPMr3rfhzc4E1XVmuqhSO8QdrscnLxjn-dIWrUmzFXAnUKFaY0tMH6mrZug3RNNKHSrbs1bisZrsqZXGM0vTEGyL3sxjwd7gi4DM7Y7Xvv9qcdDTEpZ7t14QfucNl6V1FuVaNGwzst4Be9KDCNRTywIJ_Uogyy8OW9pKCVBpPJP9e_O607hAEgCE9nEGffnnZEVzs5QNu_PagUuZJABzsWZ4q--p8CVbzj1gED7DmLMNnUOxzlZ90ewFvDrdcw"
}`

const (
	testNonceSecret = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!!"
	testTenantID    = "tenant-1"
)

func TestCredentialRequestWithoutProofTypesSupported(t *testing.T) {
	req := CredentialRequest{
		CredentialConfigurationID: "UniversityDegreeCredential",
	}

	valid, err := req.CheckRequestValid("", testTenantID, "", nil)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !valid {
		t.Fatal("expected request to be valid")
	}
}

func TestCredentialRequestWithCredentialIdentifier(t *testing.T) {
	req := CredentialRequest{
		CredentialIdentifier: "credential-123",
	}

	valid, err := req.CheckRequestValid("", testTenantID, "", nil)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !valid {
		t.Fatal("expected request to be valid")
	}
}

func TestCredentialRequestWithIdentifierAndConfigurationID(t *testing.T) {
	req := CredentialRequest{
		CredentialIdentifier:      "credential-123",
		CredentialConfigurationID: "UniversityDegreeCredential",
	}

	valid, err := req.CheckRequestValid("", testTenantID, "", nil)

	if err == nil {
		t.Fatal("expected validation error")
	}

	if valid {
		t.Fatal("expected request to be invalid")
	}
}

func TestCredentialRequestWithoutIdentifierOrConfigurationID(t *testing.T) {
	req := CredentialRequest{}

	valid, err := req.CheckRequestValid("", testTenantID, "", nil)

	if err == nil {
		t.Fatal("expected validation error")
	}

	if valid {
		t.Fatal("expected request to be invalid")
	}
}

func TestCredentialRequestRequiresProof(t *testing.T) {
	proofTypesSupported := map[ProofVariant]ProofType{
		ProofTypeJWT: {
			ProofSigningAlgValuesSupported: []string{"PS256"},
		},
	}

	req := CredentialRequest{
		CredentialConfigurationID: "UniversityDegreeCredential",
	}

	valid, err := req.CheckRequestValid(
		"https://issuer.example",
		testTenantID,
		"",
		proofTypesSupported,
	)

	if err == nil {
		t.Fatal("expected missing proof error")
	}

	if valid {
		t.Fatal("expected request to be invalid")
	}
}

func TestJWTProofValidationWithNonce(t *testing.T) {
	proofTypesSupported := map[ProofVariant]ProofType{
		ProofTypeJWT: {
			ProofSigningAlgValuesSupported: []string{"PS256"},
		},
	}

	nonce := createTestNonce(t, testTenantID)

	signedProof := createJWTProof(
		t,
		"https://issuer.example",
		nonce,
	)

	req := CredentialRequest{
		CredentialConfigurationID: "UniversityDegreeCredential",
		Proofs: &CredentialProofs{
			JWT: []string{signedProof},
		},
	}

	valid, err := req.CheckRequestValid(
		"https://issuer.example",
		testTenantID,
		testNonceSecret,
		proofTypesSupported,
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !valid {
		t.Fatal("expected request to be valid")
	}
}

func TestJWTProofValidationWithWrongAudience(t *testing.T) {
	proofTypesSupported := map[ProofVariant]ProofType{
		ProofTypeJWT: {
			ProofSigningAlgValuesSupported: []string{"PS256"},
		},
	}

	nonce := createTestNonce(t, testTenantID)

	signedProof := createJWTProof(
		t,
		"https://issuer.example",
		nonce,
	)

	req := CredentialRequest{
		CredentialConfigurationID: "UniversityDegreeCredential",
		Proofs: &CredentialProofs{
			JWT: []string{signedProof},
		},
	}

	valid, err := req.CheckRequestValid(
		"https://different-issuer.example",
		testTenantID,
		testNonceSecret,
		proofTypesSupported,
	)

	if err == nil {
		t.Fatal("expected audience validation error")
	}

	if valid {
		t.Fatal("expected request to be invalid")
	}
}

func TestJWTProofValidationWithWrongNonceSecret(t *testing.T) {
	proofTypesSupported := map[ProofVariant]ProofType{
		ProofTypeJWT: {
			ProofSigningAlgValuesSupported: []string{"PS256"},
		},
	}

	nonce := createTestNonce(t, testTenantID)

	signedProof := createJWTProof(
		t,
		"https://issuer.example",
		nonce,
	)

	req := CredentialRequest{
		CredentialConfigurationID: "UniversityDegreeCredential",
		Proofs: &CredentialProofs{
			JWT: []string{signedProof},
		},
	}

	valid, err := req.CheckRequestValid(
		"https://issuer.example",
		testTenantID,
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz!!",
		proofTypesSupported,
	)

	if err == nil {
		t.Fatal("expected nonce validation error")
	}

	if valid {
		t.Fatal("expected request to be invalid")
	}
}

func TestJWTProofValidationWithWrongTenant(t *testing.T) {
	proofTypesSupported := map[ProofVariant]ProofType{
		ProofTypeJWT: {
			ProofSigningAlgValuesSupported: []string{"PS256"},
		},
	}

	nonce := createTestNonce(t, testTenantID)

	signedProof := createJWTProof(
		t,
		"https://issuer.example",
		nonce,
	)

	req := CredentialRequest{
		CredentialConfigurationID: "UniversityDegreeCredential",
		Proofs: &CredentialProofs{
			JWT: []string{signedProof},
		},
	}

	valid, err := req.CheckRequestValid(
		"https://issuer.example",
		"tenant-2",
		testNonceSecret,
		proofTypesSupported,
	)

	if err == nil {
		t.Fatal("expected tenant validation error")
	}

	if valid {
		t.Fatal("expected request to be invalid")
	}
}

func TestJWTProofValidationWithTamperedNonce(t *testing.T) {
	proofTypesSupported := map[ProofVariant]ProofType{
		ProofTypeJWT: {
			ProofSigningAlgValuesSupported: []string{"PS256"},
		},
	}

	nonce := createTestNonce(t, testTenantID)

	parts := strings.Split(nonce, ".")
	if len(parts) != 2 {
		t.Fatalf("unexpected nonce format: %s", nonce)
	}

	parts[0] = parts[0] + "A"

	tamperedNonce := strings.Join(parts, ".")

	signedProof := createJWTProof(
		t,
		"https://issuer.example",
		tamperedNonce,
	)

	req := CredentialRequest{
		CredentialConfigurationID: "UniversityDegreeCredential",
		Proofs: &CredentialProofs{
			JWT: []string{signedProof},
		},
	}

	valid, err := req.CheckRequestValid(
		"https://issuer.example",
		testTenantID,
		testNonceSecret,
		proofTypesSupported,
	)

	if err == nil {
		t.Fatal("expected tampered nonce to be rejected")
	}

	if valid {
		t.Fatal("expected request to be invalid")
	}
}

func TestJWTProofValidationWithExpiredNonce(t *testing.T) {
	proofTypesSupported := map[ProofVariant]ProofType{
		ProofTypeJWT: {
			ProofSigningAlgValuesSupported: []string{"PS256"},
		},
	}

	nonce, err := CreateNonce(
		testNonceSecret,
		testTenantID,
		time.Nanosecond,
	)
	if err != nil {
		t.Fatalf("failed to create nonce: %v", err)
	}

	time.Sleep(time.Millisecond)

	signedProof := createJWTProof(
		t,
		"https://issuer.example",
		nonce,
	)

	req := CredentialRequest{
		CredentialConfigurationID: "UniversityDegreeCredential",
		Proofs: &CredentialProofs{
			JWT: []string{signedProof},
		},
	}

	valid, err := req.CheckRequestValid(
		"https://issuer.example",
		testTenantID,
		testNonceSecret,
		proofTypesSupported,
	)

	if err == nil {
		t.Fatal("expected expired nonce to be rejected")
	}

	if valid {
		t.Fatal("expected request to be invalid")
	}
}

func TestJWTProofValidationMissingNonceWhenNonceEnabled(t *testing.T) {
	proofTypesSupported := map[ProofVariant]ProofType{
		ProofTypeJWT: {
			ProofSigningAlgValuesSupported: []string{"PS256"},
		},
	}

	signedProof := createJWTProofWithoutNonce(
		t,
		"https://issuer.example",
	)

	req := CredentialRequest{
		CredentialConfigurationID: "UniversityDegreeCredential",
		Proofs: &CredentialProofs{
			JWT: []string{signedProof},
		},
	}

	valid, err := req.CheckRequestValid(
		"https://issuer.example",
		testTenantID,
		testNonceSecret,
		proofTypesSupported,
	)

	if err == nil {
		t.Fatal("expected missing nonce error")
	}

	if valid {
		t.Fatal("expected request to be invalid")
	}
}

func TestJWTProofValidationWithoutNonce(t *testing.T) {
	proofTypesSupported := map[ProofVariant]ProofType{
		ProofTypeJWT: {
			ProofSigningAlgValuesSupported: []string{"PS256"},
		},
	}

	signedProof := createJWTProofWithoutNonce(
		t,
		"https://issuer.example",
	)

	req := CredentialRequest{
		CredentialConfigurationID: "UniversityDegreeCredential",
		Proofs: &CredentialProofs{
			JWT: []string{signedProof},
		},
	}

	valid, err := req.CheckRequestValid(
		"https://issuer.example",
		testTenantID,
		"",
		proofTypesSupported,
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !valid {
		t.Fatal("expected request to be valid")
	}
}

func TestCreateAndValidateNonce(t *testing.T) {
	nonce, err := CreateNonce(
		testNonceSecret,
		testTenantID,
		time.Minute,
	)
	if err != nil {
		t.Fatalf("failed to create nonce: %v", err)
	}

	if nonce == "" {
		t.Fatal("expected nonce to be generated")
	}

	if err := ValidateNonce(
		testNonceSecret,
		testTenantID,
		nonce,
	); err != nil {
		t.Fatalf("expected nonce to be valid: %v", err)
	}
}

func TestValidateNonceRejectsWrongTenant(t *testing.T) {
	nonce := createTestNonce(t, testTenantID)

	err := ValidateNonce(
		testNonceSecret,
		"tenant-2",
		nonce,
	)

	if err == nil {
		t.Fatal("expected wrong tenant to be rejected")
	}
}

func TestCreateNonceGeneratesDifferentValues(t *testing.T) {
	nonce1 := createTestNonce(t, testTenantID)
	nonce2 := createTestNonce(t, testTenantID)

	if nonce1 == nonce2 {
		t.Fatal("expected generated nonces to be different")
	}
}

func TestCreateNonceRejectsShortSecret(t *testing.T) {
	_, err := CreateNonce(
		"too-short",
		testTenantID,
		time.Minute,
	)

	if err == nil {
		t.Fatal("expected short nonce secret to be rejected")
	}
}

func TestCreateNonceRejectsEmptyTenant(t *testing.T) {
	_, err := CreateNonce(
		testNonceSecret,
		"",
		time.Minute,
	)

	if err == nil {
		t.Fatal("expected empty tenant id to be rejected")
	}
}

func TestValidateNonceRejectsShortSecret(t *testing.T) {
	nonce := createTestNonce(t, testTenantID)

	err := ValidateNonce(
		"too-short",
		testTenantID,
		nonce,
	)

	if err == nil {
		t.Fatal("expected short nonce secret to be rejected")
	}
}

func TestValidateNonceRejectsEmptyTenant(t *testing.T) {
	nonce := createTestNonce(t, testTenantID)

	err := ValidateNonce(
		testNonceSecret,
		"",
		nonce,
	)

	if err == nil {
		t.Fatal("expected empty tenant id to be rejected")
	}
}

func TestValidateNonceRejectsInvalidFormat(t *testing.T) {
	err := ValidateNonce(
		testNonceSecret,
		testTenantID,
		"this-is-not-a-valid-nonce",
	)

	if err == nil {
		t.Fatal("expected invalid nonce format to be rejected")
	}
}

func TestMultipleProofTypesRejected(t *testing.T) {
	proofTypesSupported := map[ProofVariant]ProofType{
		ProofTypeJWT: {
			ProofSigningAlgValuesSupported: []string{"PS256"},
		},
		ProofTypeAttestation: {
			ProofSigningAlgValuesSupported: []string{"PS256"},
		},
	}

	req := CredentialRequest{
		CredentialConfigurationID: "UniversityDegreeCredential",
		Proofs: &CredentialProofs{
			JWT: []string{
				"jwt",
			},
			Attestation: []string{
				"attestation",
			},
		},
	}

	valid, err := req.CheckRequestValid(
		"https://issuer.example",
		testTenantID,
		"",
		proofTypesSupported,
	)

	if err == nil {
		t.Fatal("expected multiple proof types to be rejected")
	}

	if valid {
		t.Fatal("expected request to be invalid")
	}
}

func TestUnsupportedJWTProofRejected(t *testing.T) {
	proofTypesSupported := map[ProofVariant]ProofType{
		ProofTypeDIVP: {},
	}

	req := CredentialRequest{
		CredentialConfigurationID: "UniversityDegreeCredential",
		Proofs: &CredentialProofs{
			JWT: []string{"jwt"},
		},
	}

	valid, err := req.CheckRequestValid(
		"https://issuer.example",
		testTenantID,
		"",
		proofTypesSupported,
	)

	if err == nil {
		t.Fatal("expected unsupported proof type error")
	}

	if valid {
		t.Fatal("expected request to be invalid")
	}
}

func createTestNonce(
	t *testing.T,
	tenantID string,
) string {
	t.Helper()

	nonce, err := CreateNonce(
		testNonceSecret,
		tenantID,
		time.Minute,
	)
	if err != nil {
		t.Fatalf("failed to create nonce: %v", err)
	}

	return nonce
}

func createJWTProof(
	t *testing.T,
	audience string,
	nonce string,
) string {
	t.Helper()

	token, err := jwt.NewBuilder().
		Issuer("test.com").
		IssuedAt(time.Now()).
		Audience([]string{audience}).
		Claim("nonce", nonce).
		Build()

	if err != nil {
		t.Fatalf("failed to build token: %v", err)
	}

	return signJWTProof(t, token)
}

func createJWTProofWithoutNonce(
	t *testing.T,
	audience string,
) string {
	t.Helper()

	token, err := jwt.NewBuilder().
		Issuer("test.com").
		IssuedAt(time.Now()).
		Audience([]string{audience}).
		Build()

	if err != nil {
		t.Fatalf("failed to build token: %v", err)
	}

	return signJWTProof(t, token)
}

func signJWTProof(
	t *testing.T,
	token jwt.Token,
) string {
	t.Helper()

	privKey, err := jwk.ParseKey([]byte(jwkPrivKey))
	if err != nil {
		t.Fatalf("failed to parse private key: %v", err)
	}

	pubKey, err := privKey.PublicKey()
	if err != nil {
		t.Fatalf("failed to create public key: %v", err)
	}

	headers := jws.NewHeaders()

	if err := headers.Set("typ", "openid4vci-proof+jwt"); err != nil {
		t.Fatalf("failed to set typ header: %v", err)
	}

	if err := headers.Set("jwk", pubKey); err != nil {
		t.Fatalf("failed to set jwk header: %v", err)
	}

	signed, err := jwt.Sign(
		token,
		jwt.WithKey(
			jwa.PS256,
			privKey,
			jws.WithProtectedHeaders(headers),
		),
	)

	if err != nil {
		t.Fatalf("failed to sign JWT proof: %v", err)
	}

	if len(signed) == 0 {
		t.Fatal("signed JWT proof is empty")
	}

	return string(signed)
}
