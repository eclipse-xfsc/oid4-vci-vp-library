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
    "authorization_servers": [
        "https://server.example.com"
    ],
    "credential_endpoint": "https://credential-issuer.example.com/credential",
    "deferred_credential_endpoint": "https://credential-issuer.example.com/deferred_credential",

    "credential_response_encryption": {
        "alg_values_supported": [
            "ECDH-ES"
        ],
        "enc_values_supported": [
            "A128GCM"
        ],
        "encryption_required": false
    },

    "batch_credential_issuance": {
        "batch_size": 10
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
            "format": "dc+sd-jwt",
            "scope": "SD_JWT_VC_example_in_OpenID4VCI",

            "cryptographic_binding_methods_supported": [
                "jwk"
            ],

            "credential_signing_alg_values_supported": [
                "ES256"
            ],

            "proof_types_supported": {
                "jwt": {
                    "proof_signing_alg_values_supported": [
                        "ES256"
                    ]
                }
            },

            "display": [
                {
                    "name": "IdentityCredential",
                    "locale": "en-US",
                    "background_color": "#12107c",
                    "text_color": "#FFFFFF"
                }
            ],

            "vct": "SD_JWT_VC_example_in_OpenID4VCI",

            "claims": [
                {
                    "path": [
                        "given_name"
                    ],
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
                {
                    "path": [
                        "family_name"
                    ],
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
                {
                    "path": [
                        "email"
                    ]
                },
                {
                    "path": [
                        "phone_number"
                    ]
                },
                {
                    "path": [
                        "address",
                        "street_address"
                    ]
                },
                {
                    "path": [
                        "address",
                        "locality"
                    ]
                },
                {
                    "path": [
                        "address",
                        "region"
                    ]
                },
                {
                    "path": [
                        "address",
                        "country"
                    ]
                },
                {
                    "path": [
                        "birthdate"
                    ]
                },
                {
                    "path": [
                        "is_over_18"
                    ]
                },
                {
                    "path": [
                        "is_over_21"
                    ]
                },
                {
                    "path": [
                        "is_over_65"
                    ]
                }
            ]
        },

        "UniversityDegreeCredential": {
            "format": "jwt_vc_json",
            "scope": "UniversityDegree",

            "cryptographic_binding_methods_supported": [
                "did"
            ],

            "credential_signing_alg_values_supported": [
                "ES256"
            ],

            "credential_definition": {
                "type": [
                    "VerifiableCredential",
                    "UniversityDegreeCredential"
                ]
            },

            "proof_types_supported": {
                "jwt": {
                    "proof_signing_alg_values_supported": [
                        "ES256"
                    ]
                }
            },

            "claims": [
                {
                    "path": [
                        "credentialSubject",
                        "given_name"
                    ],
                    "display": [
                        {
                            "name": "Given Name",
                            "locale": "en-US"
                        }
                    ]
                },
                {
                    "path": [
                        "credentialSubject",
                        "family_name"
                    ],
                    "display": [
                        {
                            "name": "Surname",
                            "locale": "en-US"
                        }
                    ]
                },
                {
                    "path": [
                        "credentialSubject",
                        "degree"
                    ]
                },
                {
                    "path": [
                        "credentialSubject",
                        "gpa"
                    ],
                    "display": [
                        {
                            "name": "GPA"
                        }
                    ]
                }
            ],

            "display": [
                {
                    "name": "University Credential",
                    "locale": "en-US",
                    "logo": {
                        "uri": "https://university.example.edu/public/logo.png",
                        "alt_text": "a square logo of a university"
                    },
                    "background_color": "#12107c",
                    "text_color": "#FFFFFF"
                }
            ]
        }
    }
}`

func TestFindOpenIDConfiguration(t *testing.T) {
	srv := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")

			configuration := oauth.OpenIdConfiguration{
				Issuer:              "issuer-1",
				GrantTypesSupported: []string{"authorization_code"},
				JwksUri:             "test",
			}

			if err := json.NewEncoder(w).Encode(configuration); err != nil {
				t.Fatalf(
					"failed to encode authorization server metadata: %v",
					err,
				)
			}
		}),
	)
	defer srv.Close()

	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		configuration := oauth.OpenIdConfiguration{
			GrantTypesSupported: []string{
				string(oauth.PreAuthorizedCodeGrant),
			},
			JwksUri: "test2",
		}

		if err := json.NewEncoder(w).Encode(configuration); err != nil {
			t.Fatalf("failed to encode authorization server metadata: %v", err)
		}
	}))
	defer srv2.Close()
	defer srv2.Close()

	metadata := IssuerMetadata{
		AuthorizationServers: []string{
			srv.URL,
			srv2.URL,
		},
	}

	configuration, err := metadata.FindFittingAuthorizationServer(
		oauth.PreAuthorizedCodeGrant,
	)

	if err != nil {
		t.Fatalf(
			"FindFittingAuthorizationServer() returned error: %v",
			err,
		)
	}

	if configuration == nil {
		t.Fatal("expected authorization server configuration")
	}

	if configuration.JwksUri != "test2" {
		t.Errorf(
			"unexpected jwks_uri: got %q, want %q",
			configuration.JwksUri,
			"test2",
		)
	}
}

func TestFindOpenIDConfigurationIssuer(t *testing.T) {
	srv := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")

			configuration := oauth.OpenIdConfiguration{
				GrantTypesSupported: []string{
					string(oauth.PreAuthorizedCodeGrant),
				},
				JwksUri: "test",
			}

			if err := json.NewEncoder(w).Encode(configuration); err != nil {
				t.Fatalf(
					"failed to encode authorization server metadata: %v",
					err,
				)
			}
		}),
	)
	defer srv.Close()

	metadata := IssuerMetadata{
		CredentialIssuer: srv.URL,
	}

	configuration, err := metadata.FindFittingAuthorizationServer(
		oauth.PreAuthorizedCodeGrant,
	)

	if err != nil {
		t.Fatalf(
			"FindFittingAuthorizationServer() returned error: %v",
			err,
		)
	}

	if configuration == nil {
		t.Fatal("expected authorization server configuration")
	}

	if configuration.JwksUri != "test" {
		t.Errorf(
			"unexpected jwks_uri: got %q, want %q",
			configuration.JwksUri,
			"test",
		)
	}
}

func TestIssuerMetadataUnmarshal(t *testing.T) {
	var metadata IssuerMetadata

	if err := json.Unmarshal(
		[]byte(exampleIssuerMetadata),
		&metadata,
	); err != nil {
		t.Fatalf(
			"failed to unmarshal issuer metadata: %v",
			err,
		)
	}

	if metadata.CredentialIssuer != "https://credential-issuer.example.com" {
		t.Errorf(
			"unexpected credential issuer: %q",
			metadata.CredentialIssuer,
		)
	}

	if metadata.CredentialEndpoint != "https://credential-issuer.example.com/credential" {
		t.Errorf(
			"unexpected credential endpoint: %q",
			metadata.CredentialEndpoint,
		)
	}

	if len(metadata.AuthorizationServers) != 1 {
		t.Fatalf(
			"expected one authorization server, got %d",
			len(metadata.AuthorizationServers),
		)
	}

	if len(metadata.CredentialConfigurationsSupported) != 2 {
		t.Fatalf(
			"expected two credential configurations, got %d",
			len(metadata.CredentialConfigurationsSupported),
		)
	}

	if metadata.BatchCredentialIssuance == nil {
		t.Fatal("expected batch_credential_issuance")
	}

	if metadata.BatchCredentialIssuance.BatchSize != 10 {
		t.Errorf(
			"unexpected batch size: got %d, want 10",
			metadata.BatchCredentialIssuance.BatchSize,
		)
	}

	if metadata.CredentialResponseEncryption == nil {
		t.Fatal("expected credential_response_encryption")
	}

	sdJWT, ok := metadata.CredentialConfigurationsSupported["SD_JWT_VC_example_in_OpenID4VCI"]

	if !ok {
		t.Fatal(
			"SD_JWT_VC_example_in_OpenID4VCI configuration missing",
		)
	}

	if sdJWT.Format != "dc+sd-jwt" {
		t.Errorf(
			"unexpected SD-JWT format: %q",
			sdJWT.Format,
		)
	}

	university, ok := metadata.CredentialConfigurationsSupported["UniversityDegreeCredential"]

	if !ok {
		t.Fatal(
			"UniversityDegreeCredential configuration missing",
		)
	}

	if university.Format != "jwt_vc_json" {
		t.Errorf(
			"unexpected UniversityDegreeCredential format: %q",
			university.Format,
		)
	}
}
