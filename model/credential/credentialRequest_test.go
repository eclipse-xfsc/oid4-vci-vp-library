package credential

import (
	"fmt"
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

func TestNonceValidationWithProof(t *testing.T) {

	proofTypesSupported := map[ProofVariant]ProofType{
		ProofTypeJWT: ProofType{
			ProofSigningAlgValuesSupported: []string{"ES256"},
		},
	}

	tok, err := jwt.NewBuilder().
		Issuer("test.com").
		IssuedAt(time.Now()).
		Audience([]string{"audience"}).
		Build()
	tok.Set("nonce", "123456")

	if err != nil {
		fmt.Printf("failed to build token: %s\n", err)
		return
	}
	privkey, err := jwk.ParseKey([]byte(jwkPrivKey))

	if err != nil {
		t.Error()
	}

	pubkey, _ := privkey.PublicKey()

	headers := jws.NewHeaders()
	headers.Set("jwk", pubkey)

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.PS256, privkey, jws.WithProtectedHeaders(headers)))

	if err != nil || signed == nil || len(signed) == 0 {
		t.Error()
		return
	}
	p := string(signed)
	proof := Proof{
		ProofType: ProofTypeJWT,
		Jwt:       &p,
	}

	err2 := proof.CheckProof("audience", "123456", proofTypesSupported)

	if err2 != nil {
		t.Error()
	}

	err2 = proof.CheckProof("bla", "123456", proofTypesSupported)

	if err2 == nil {
		t.Error()
	}

	err2 = proof.CheckProof("audience", "1", proofTypesSupported)

	if err2 == nil {
		t.Error()
	}
}

func TestSdJwtProfilingWithoutProofTypesSupported(t *testing.T) {

	s := "test"

	//Test vct with optional claims, no prooftype
	validReq := CredentialRequest{
		Format: "vc+sd-jwt",
		Vct:    &s,
	}

	b, err := validReq.CheckRequestValid("", "", nil)

	if err != nil && !b {
		t.Error()
	}

}

func TestSdJwtProfilingWithIdentifier(t *testing.T) {

	s := "test"

	//Test vct with optional claims, no prooftype
	validReq := CredentialRequest{
		Format:               "vc+sd-jwt",
		Vct:                  &s,
		CredentialIdentifier: "xxxx",
	}

	b, err := validReq.CheckRequestValid("", "", nil)

	if err == nil || b {
		t.Error()
	}

}

func TestSdJwtProfilingWithJWTProofTypesSupported(t *testing.T) {

	proofTypesSupported := map[ProofVariant]ProofType{
		ProofTypeJWT: ProofType{
			ProofSigningAlgValuesSupported: []string{"ES256"},
		},
	}

	s := "test"

	//Test vct with optional claims, no prooftype
	validReq := CredentialRequest{
		Format: "vc+sd-jwt",
		Vct:    &s,
	}

	b, err := validReq.CheckRequestValid("", "", proofTypesSupported)

	if err != nil && !b {
		t.Error()
	}

}
