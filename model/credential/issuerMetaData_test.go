package credential

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/oauth"
)

var exampleIssuerMetadata = `{
    "credential_issuer": "https://credential-issuer.example.com",
    "authorization_servers": [ "https://server.example.com" ],
    "credential_endpoint": "https://credential-issuer.example.com",
    "batch_credential_endpoint": "https://credential-issuer.example.com/batch_credential",
    "deferred_credential_endpoint": "https://credential-issuer.example.com/deferred_credential",
    "credential_response_encryption": {
        "alg_values_supported" : [
            "ECDH-ES"
        ],
        "enc_values_supported" : [
            "A128GCM"
        ],
        "encryption_required": false
    },
    "display": [
        {
            "name": "Example University",
            "locale": "en-US"
        },
        {
            "name": "Example Université",
            "locale": "fr-FR"
        }
    ],
    "credential_configurations_supported": {
		"SD_JWT_VC_example_in_OpenID4VCI": {
            "format": "vc+sd-jwt",
            "scope": "SD_JWT_VC_example_in_OpenID4VCI",
            "cryptographic_binding_methods_supported": [
                "jwk"
            ],
            "credential_signing_alg_values_supported": [
                "ES256"
            ],
            "display": [
                {
                    "name": "IdentityCredential",
                    "locale": "en-US",
                    "background_color": "#12107c",
                    "text_color": "#FFFFFF"
                }
            ],
            "vct": "SD_JWT_VC_example_in_OpenID4VCI",
            "claims": {
                "given_name": {
                    "display": [
                        {
                            "name": "Given Name",
                            "locale": "en-US"
                        },
                        {
                            "name": "Vorname",
                            "locale": "de-DE"
                        }
                    ]
                },
                "family_name": {
                    "display": [
                        {
                            "name": "Surname",
                            "locale": "en-US"
                        },
                        {
                            "name": "Nachname",
                            "locale": "de-DE"
                        }
                    ]
                },
                "email": {},
                "phone_number": {},
                "address": {
                    "street_address": {},
                    "locality": {},
                    "region": {},
                    "country": {}
                },
                "birthdate": {},
                "is_over_18": {},
                "is_over_21": {},
                "is_over_65": {}
            }
        },
        "UniversityDegreeCredential": {
            "format": "jwt_vc_json",
            "scope": "UniversityDegree",
            "cryptographic_binding_methods_supported": [
                "did:example"
            ],
            "credential_signing_alg_values_supported": [
                "ES256"
            ],
            "credential_definition":{
                "type": [
                    "VerifiableCredential",
                    "UniversityDegreeCredential"
                ],
                "credentialSubject": {
                    "given_name": {
                        "display": [
                            {
                                "name": "Given Name",
                                "locale": "en-US"
                            }
                        ]
                    },
                    "family_name": {
                        "display": [
                            {
                                "name": "Surname",
                                "locale": "en-US"
                            }
                        ]
                    },
                    "degree": {},
                    "gpa": {
                        "display": [
                            {
                                "name": "GPA"
                            }
                        ]
                    }
                }
            },
            "proof_types_supported": {
                "jwt": {
                    "proof_signing_alg_values_supported": [
                        "ES256"
                    ]
                }
            },
            "display": [
                {
                    "name": "University Credential",
                    "locale": "en-US",
                    "logo": {
                        "url": "https://university.example.edu/public/logo.png",
                        "alt_text": "a square logo of a university"
                    },
                    "background_color": "#12107c",
                    "text_color": "#FFFFFF"
                }
            ]
        }
    }}`

func Test_FindOpenIdConfiguration(t *testing.T) {

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)

		m := oauth.OpenIdConfiguration{
			Grant_Types_Supported: []string{string("bla")},
			Jwks_Uri:              "test",
		}

		b, _ := json.Marshal(m)

		w.Write(b)
	}))

	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)

		m := oauth.OpenIdConfiguration{
			Grant_Types_Supported: []string{string(oauth.PreAuthorizedCodeGrant)},
			Jwks_Uri:              "test2",
		}

		b, _ := json.Marshal(m)

		w.Write(b)
	}))

	metadata := IssuerMetadata{
		AuthorizationServers: []string{srv.URL, srv2.URL},
	}

	config, err := metadata.FindFittingAuthorizationServer(oauth.PreAuthorizedCodeGrant)

	if err != nil || config.Jwks_Uri != "test2" {
		t.Error()
	}

}

func Test_FindOpenIdConfiguration_Issuer(t *testing.T) {

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)

		m := oauth.OpenIdConfiguration{
			Grant_Types_Supported: []string{string(oauth.PreAuthorizedCodeGrant)},
			Jwks_Uri:              "test",
		}

		b, _ := json.Marshal(m)

		w.Write(b)
	}))

	metadata := IssuerMetadata{
		CredentialIssuer: srv.URL,
	}

	config, err := metadata.FindFittingAuthorizationServer(oauth.PreAuthorizedCodeGrant)

	if err != nil || config.Jwks_Uri != "test" {
		t.Error()
	}
}

func TestMarshalling(t *testing.T) {
	var metadata IssuerMetadata
	err := json.Unmarshal([]byte(exampleIssuerMetadata), &metadata)

	if err != nil {
		t.Error()
		return
	}

	if len(metadata.CredentialConfigurationsSupported) != 2 {
		t.Error()
		return
	}
}
