# OID4VCI / OID4VP Library

Go models and helpers used by XFSC services for **OpenID for Verifiable Credential Issuance (OpenID4VCI)** and **OpenID for Verifiable Presentations (OpenID4VP)** flows.

The current `oidvci10` branch contains the OpenID4VCI 1.0 model updates. It replaces the previous README statement that described the library as a partial Draft 13 implementation.

> **Note:** OpenID4VCI 1.0 support is actively evolving. The library also keeps selected legacy fields for interoperability with wallet implementations that still use older request structures. Consumers should prefer the 1.0 structures documented below.

## Requirements

- Go 1.24+
- The module currently declares the Go 1.24.2 toolchain.

```bash
go get github.com/eclipse-xfsc/oid4-vci-vp-library
```

## OpenID4VCI 1.0 support

### Credential Offer

The credential offer model uses the OpenID4VCI 1.0 fields:

- `credential_issuer`
- `credential_configuration_ids`
- `authorization_code`
- `urn:ietf:params:oauth:grant-type:pre-authorized_code`
- `tx_code`
- optional `authorization_server`

`CredentialOfferParameters.Validate()` checks required values, duplicate configuration IDs, pre-authorized code presence and `tx_code` constraints.

```go
offer := credential.CredentialOfferParameters{
    CredentialIssuer: "https://issuer.example.com",
    CredentialConfigurationIDs: []string{"UniversityDegreeCredential"},
}

link, err := offer.CreateOfferLink()
if err != nil {
    // handle error
}
```

The library can parse both an embedded `credential_offer` and a referenced `credential_offer_uri` through `CredentialOffer.GetOfferParameters()`.

### Credential Issuer Metadata

`credential.IssuerMetadata` models the OpenID4VCI issuer metadata, including:

- `credential_issuer`
- `authorization_servers`
- `credential_endpoint`
- `nonce_endpoint`
- `deferred_credential_endpoint`
- `notification_endpoint`
- `credential_configurations_supported`
- credential request/response encryption metadata
- batch credential issuance metadata
- signed metadata

Credential configurations support format-specific data such as `vct`, credential definitions, claims, display information, cryptographic binding methods, signing algorithms and proof types.

### Authorization Details and Token Response

The OAuth models support `authorization_details` with `type=openid_credential`, including:

- `credential_configuration_id`
- `credential_identifiers`
- `claims`
- `locations`

The token helper currently supports the pre-authorized code grant and `tx_code`.

### Credential Request

For OpenID4VCI 1.0, credential selection is represented by exactly one of:

- `credential_identifier`
- `credential_configuration_id`

Proofs use the plural `proofs` structure:

```json
{
  "credential_identifier": "credential-1",
  "proofs": {
    "jwt": ["eyJ..."]
  }
}
```

The model supports the proof variants:

- `jwt`
- `di_vp`
- `attestation`

```go
request := credential.CredentialRequest{
    CredentialIdentifier: "credential-1",
    Proofs: &credential.CredentialProofs{
        JWT: []string{signedProof},
    },
}
```

The older singular `proof` and `format` fields remain in `CredentialRequest` only for interoperability with legacy wallet implementations. `CredentialRequest.Normalize()` converts a supported legacy JWT proof into the OpenID4VCI 1.0 `proofs` representation. New integrations should use `proofs` directly.

### JWT Key Proof validation

JWT key proofs use `typ=openid4vci-proof+jwt`. The proof validation implementation covers the protocol-relevant checks represented by the library, including:

- supported proof type and signing algorithm
- JWT proof signature validation
- audience binding
- issued-at (`iat`) validation
- optional issuer (`iss`)
- nonce validation when a Nonce Endpoint is used
- proof key material supplied through the supported JOSE header mechanisms

Proof algorithms are constrained by the selected credential configuration's `proof_types_supported` metadata.

### Nonce Endpoint support

Issuer metadata exposes `nonce_endpoint`. The library provides helpers for creating and validating opaque HMAC-SHA256 protected nonces:

```go
nonce, err := credential.CreateNonce(
    nonceSecret,
    tenantID,
    credential.DefaultNonceTTL,
)
```

`ValidateNonce()` checks integrity, tenant binding and expiration.

The nonce helper requires a secret of at least 32 characters. The generated nonce contains a random JTI and expiration. Applications requiring strict one-time use must additionally persist and consume the JTI server-side; cryptographic validation alone does not provide replay protection.

### Credential Response

The OpenID4VCI response model supports:

- immediate issuance through `credentials`
- deferred issuance through `transaction_id`
- `interval`
- `notification_id`
- JSON-string and JSON-object credential values

Relevant protocol error values include `invalid_credential_request`, `unknown_credential_configuration`, `unknown_credential_identifier`, `invalid_proof`, `invalid_nonce`, `invalid_encryption_parameters`, `credential_request_denied` and `invalid_transaction_id`.

## OpenID4VP 1.0 Final support

This package targets **OpenID for Verifiable Presentations 1.0 Final**. The protocol model uses DCQL and the final OID4VP response representation. Presentation Exchange structures remain in the repository for legacy integrations, but they are not the request model for OID4VP 1.0 Final.

### Supported final credential format identifiers

The OID4VP 1.0 data model recognizes the format identifiers defined by the Final specification:

- `dc+sd-jwt` — IETF SD-JWT VC presentation.
- `mso_mdoc` — ISO mdoc presentation.
- `jwt_vc_json` — W3C VC secured as JWT.
- `ldp_vc` — W3C VC secured with Data Integrity / Linked Data proof mechanisms.

`jwt_vc_json-ld` is not an OID4VP 1.0 Final Credential Format Identifier and is no longer exposed as a final-format constant. `types.CheckFormat` no longer treats an arbitrary JSON object as `ldp_vc`; a JSON credential must at least identify itself as a W3C Verifiable Credential through `@context` and `type`.

### Authorization Request validation

`AuthorizationRequest.Validate()` applies the following protocol rules represented by this library:

- `client_id` is required and is parsed as an OID4VP Client Identifier. Supported standard prefixes are `pre-registered`, `redirect_uri`, `openid_federation`, `verifier_attestation`, `decentralized_identifier`, `x509_san_dns`, and `x509_hash`.
- `response_type` is required. A presentation request uses `vp_token`; `nonce` is required whenever `vp_token` is requested.
- A presentation request must resolve to a DCQL query. The model rejects simultaneous `scope` and `dcql_query` because a request must not express the same DCQL request through both mechanisms.
- `response_mode` defaults to `fragment` for `vp_token` when omitted.
- `direct_post` and `direct_post.jwt` require `response_uri`.
- `response_uri` and `redirect_uri` must not both be present.
- `request_uri_method` is only valid when `request_uri` is present and is restricted to the case-sensitive values `get` and `post`.
- `request` and `request_uri` are mutually exclusive in the library request model.
- `transaction_data`, when present, must be non-empty base64url-encoded JSON objects and each decoded object must contain a non-empty `type`. Applications must additionally register/understand the transaction-data type and reject unsupported types.
- `verifier_info` entries require `format` and `data`; any `credential_ids` references must resolve to credential query IDs from the request.

### Request Objects and `request_uri`

OID4VP 1.0 uses RFC 9101 Request Objects. A response from a Request URI endpoint is not a JSON Authorization Request: it is a signed and optionally encrypted Request Object with media type `application/oauth-authz-req+jwt`.

The wallet service therefore requires a `RequestObjectVerifier` whenever `request` or `request_uri` is used. The verifier implementation is responsible for JWS/JWE processing, key resolution, signature validation, certificate/DID/federation/verifier-attestation validation required by the selected Client Identifier Prefix, and normal RFC 9101 claim validation. The library does not accept an unverified Request Object as trusted protocol input.

After verification:

- The outer `client_id` and Request Object `client_id` must be identical, including the prefix.
- Only parameters from the verified Request Object are used for the resulting Authorization Request. Outer duplicate parameters are not merged into it.
- If a Wallet sent `wallet_nonce`, the Request Object verifier must require the same value in the `wallet_nonce` claim.
- For `request_uri_method=post`, the request uses `application/x-www-form-urlencoded`, advertises `Accept: application/oauth-authz-req+jwt`, and can include `wallet_nonce` and serialized `wallet_metadata`.
- HTTP error responses terminate request processing. Deployments must additionally enforce HTTPS, redirect restrictions, timeouts, response-size limits, and SSRF protections.

### Client Identifier Prefix security

The parser recognizes all Client Identifier Prefixes defined by OID4VP 1.0 Final. Prefix recognition alone is not authentication. The configured `RequestObjectVerifier` must implement the prefix-specific trust rules. In particular, prefixes such as `openid_federation`, `decentralized_identifier`, `verifier_attestation`, `x509_san_dns`, and `x509_hash` require authenticated request processing and secure key handling. For X.509 based identifiers, implementations must validate the certificate chain and the identifier binding required by the selected prefix rather than merely parsing the prefix string.

### DCQL validation rules

`DCQLQuery.Validate()` enforces the structural rules that can be validated without format-specific cryptography:

- `credentials` is required and must be a non-empty array.
- Every Credential Query requires a unique `id` matching `[A-Za-z0-9_-]+`.
- Every Credential Query requires `format`.
- Every Credential Query requires `meta`; use `{}` when no metadata constraint is requested.
- For `dc+sd-jwt`, `meta.vct_values` is required and must be a non-empty array of non-empty strings.
- `trusted_authorities`, when present, must be non-empty at the JSON/protocol boundary; every entry requires a non-empty `type` and a non-empty `values` array containing non-empty strings. Standard types include `aki`, `etsi_tl`, and `openid_federation`. Matching the query is only a disclosure-selection aid; the Verifier must independently establish issuer trust.
- `claims`, when present, contains Claims Path Pointers. A path is non-empty and each component is a string, `null`, or a non-negative integer.
- A Credential Query must not point to the same claim path more than once.
- Claim `id`, when present, matches `[A-Za-z0-9_-]+` and is unique within the Credential Query.
- If `claim_sets` is present, every claim requires an `id`, each claim-set option is non-empty, and every referenced claim ID must exist.
- `credential_sets.options` is non-empty, every option is non-empty, and every referenced Credential Query ID must exist.
- `multiple` defaults to `false` when omitted.
- `require_cryptographic_holder_binding` defaults to `true` when omitted. Format-specific presentation code must enforce this requirement.

Go slices with `omitempty` cannot distinguish every possible malformed JSON representation after decoding. Protocol endpoints that need strict distinction between an absent member and an explicitly empty optional array should reject the malformed wire representation before or during decoding; the semantic validator handles all representations retained by the model.

### Claims Path Pointer rules

`ClaimsPathPointer` implements the OID4VP path model for normalized JSON credentials:

- string selects an object member;
- non-negative integer selects an array element;
- `null` selects all elements of an array;
- an empty path is invalid;
- selection failure means the requested claim is not satisfied.

For ISO mdoc, namespace/data-element processing remains format specific and should be implemented by an mdoc adapter rather than by coercing CBOR structures into generic JSON semantics.

### Wallet and Verifier metadata

The package contains typed `WalletMetadata`, `VerifierMetadata`, and `FormatMetadata` models instead of using an unstructured `map[string]interface{}` for core OID4VP metadata. They cover `vp_formats_supported`, `client_id_prefixes_supported`, request-object signing algorithms, authorization-response encryption algorithms, response encryption `enc` values, and JWK sets.

Important metadata rules include:

- `vp_formats_supported` is required when the same information is not available to the peer through another authoritative mechanism.
- Public keys in request `client_metadata` are response-encryption keys and must not be repurposed to authenticate a signed Authorization Request.
- Every JWK supplied in `client_metadata.jwks` must have a non-empty `kid` unique in the set.
- Format-specific algorithm arrays, when supplied, are capability constraints and should be non-empty.
- Authoritative metadata obtained through a Client Identifier mechanism takes precedence over self-asserted `client_metadata`.
- Unknown metadata parameters are ignored unless a profile explicitly defines their use.

### `vp_token` response rules

OID4VP 1.0 with DCQL represents `vp_token` as a JSON object. Each property name is a Credential Query `id`; each value is a non-empty array of one or more presentations for that query. `VPToken.ValidateAgainst()` verifies the response shape, rejects unknown query IDs, enforces the `multiple` constraint, and checks required credential-set combinations.

Structural validation is not credential verification. Before accepting a presentation, the Verifier must perform the format-specific cryptographic and semantic checks described below.

### Response modes

The wallet service separates the final response modes:

- `fragment`: the library returns the generated VP Token to the caller; the application owns the browser/front-channel redirect.
- `direct_post`: the library sends `vp_token` and optional `state` as UTF-8 `application/x-www-form-urlencoded` parameters to `response_uri`.
- `direct_post.jwt`: the library requires a `ResponseEncryptor`, creates an encrypted response through that adapter, and POSTs it in the single `response` form parameter.

`direct_post.jwt` is an encrypted response, not a signed JARM response. The encryptor must produce the unsigned encrypted JWT/JWE required by OID4VP and select a Verifier encryption key and algorithms from authenticated/validated Verifier metadata. `A128GCM` is the default content-encryption value when the specification permits the default to be used.

A successful Response Endpoint reply is parsed as JSON and may contain `redirect_uri`. Unknown response members are ignored. If a response body is present, it must be JSON. Applications decide whether and how to navigate to a returned `redirect_uri` and must apply normal URI safety checks.

### SD-JWT VC validation and presentation binding

For `dc+sd-jwt`:

- `meta.vct_values` is required in the Credential Query.
- The selected Credential must have a `vct` accepted by the query, including any type-inheritance processing required by the SD-JWT VC specification.
- When `require_cryptographic_holder_binding` is true or omitted, the Wallet must return SD-JWT+KB and the Credential must support Holder Binding.
- The Key Binding JWT `nonce` must equal the Authorization Request `nonce`.
- The Key Binding JWT `aud` must equal the full OID4VP Client Identifier, including its prefix (except for the DC API rule defined by the specification).
- The Verifier must validate issuer signature, disclosures, `sd_hash`, holder key binding, time claims, credential status where applicable, issuer trust, and the DCQL claim/type constraints.
- When transaction data applies, the Wallet must bind the required transaction-data representation/hashes into the presentation and the Verifier must validate that binding.

The generic library does not manufacture these cryptographic proofs. `WalletBackend.CreateVPToken` must create a presentation with the above bindings, and the Verifier's format-specific validation layer must verify them.

### ISO mdoc validation

For `mso_mdoc`, format-specific code must validate the IssuerSigned/DeviceSigned structures, issuer authentication, device authentication or MAC/signature rules as applicable, document type metadata, requested namespaces/data elements, validity/status/trust rules, and the OID4VP session transcript/handover binding. When encrypted responses are used, the handover construction must bind the Verifier encryption key thumbprint where required by OID4VP.

### W3C VC validation

For `jwt_vc_json`, format-specific validation must verify the JWT securing mechanism and presentation binding, including audience/client binding and nonce. For `ldp_vc`, the implementation must validate the applicable Data Integrity proof/cryptosuite and the presentation challenge/domain or equivalent OID4VP binding rules. In both cases the Verifier must validate issuer trust, credential validity/status, requested credential type metadata, requested claims, and holder binding when required.

### Trusted authorities

`trusted_authorities` is a DCQL selection hint, not a replacement for Verifier trust validation. A Wallet should use the supplied authorities to avoid disclosing Credentials that the Verifier is likely to reject. The Verifier must still establish trust independently. The standard query types have type-specific matching rules; deployments should implement those rules in their credential/trust adapters rather than comparing arbitrary strings generically.

### Transaction data

`transaction_data` creates a cryptographic binding between the presentation and a transaction the End-User is authorizing. The library validates the base64url JSON envelope and type presence. Applications must maintain a registry of supported transaction-data types and must reject the entire request if any supplied type is unknown or its payload violates that type's definition. Format-specific presentation code must apply the transaction-data processing and hashing rules for the selected credential format.

### Verifier-side validation pipeline

A production Verifier should process every returned presentation through a format-specific verification pipeline before considering the OID4VP transaction successful. At minimum this pipeline must cover:

- decode and validate the `vp_token` JSON object against the original DCQL query;
- verify every credential/presentation cryptographic signature or proof;
- verify issuer identity and issuer trust independently of `trusted_authorities`;
- verify credential validity periods and status/revocation information where applicable;
- verify Holder Binding when required;
- bind the presentation to the original Authorization Request `nonce` and full `client_id`;
- enforce format metadata (`vct_values`, W3C type constraints, mdoc document type, algorithms/cryptosuites);
- verify requested claims and claim-set/credential-set satisfaction;
- validate transaction-data binding when present;
- reject replayed presentations according to the deployment's replay-detection policy.

`VerifierService.ProcessResponse` performs the DCQL/VP Token wire validation before calling the configured policy/backend. A deployment must configure its policy/backend as the format-specific cryptographic verification boundary; syntactic `vp_token` validation alone is never sufficient for acceptance.

### Extensibility boundaries

Cryptography and trust resolution are deliberately represented by interfaces rather than hard-coded into the protocol model:

- `RequestObjectVerifier` — RFC 9101 plus Client Identifier Prefix authentication and `wallet_nonce` validation.
- `ResponseEncryptor` — OID4VP encrypted Authorization Response / `direct_post.jwt`.
- `WalletBackend` — credential matching and format-specific presentation generation, including Holder Binding and transaction binding.
- `PolicyClient` / verifier backend — format-specific presentation verification and trust policy.

This keeps the protocol structures reusable with XFSC crypto-provider, SD-JWT, credential-storage, DID, federation, X.509, and mdoc implementations without treating one concrete crypto stack as part of the wire specification.

### Conformance and interoperability

Changes should be tested against the OpenID Foundation OID4VP 1.0 Final conformance suite. Certification additionally profiles HAIP 1.0 Final. Unit tests in this repository are necessary for model behavior but do not replace OIDF conformance testing, format-specific test vectors, negative cryptographic tests, or cross-implementation interoperability tests.

## Package overview

```text
config/                 default library configuration
helper/                 HTTP request helpers
model/credential/       OID4VCI offers, metadata, requests and responses
model/oauth/            OAuth authorization server and authorization_details models
model/token/            token response models
model/presentation/     OID4VP / Presentation Exchange models
model/types/            shared credential/presentation formats and response types
```

## Security considerations

Protocol models are not a replacement for wallet or issuer trust validation. Applications using this library remain responsible for applying the security policy required by their role.

In particular, wallet implementations should validate issued credentials before storing or presenting them. Depending on the credential format this includes signature/proof verification, issuer trust and issuer binding, validity periods, holder/key binding where applicable, and credential status/revocation information.

Remote URIs obtained from credential offers, issuer metadata, presentation requests, status information or other untrusted protocol input must not be fetched blindly. Services should apply HTTPS requirements, URI validation, redirect restrictions, response size/time limits and SSRF protections appropriate to their deployment.

Issuer implementations must validate credential requests and key proofs against the selected credential configuration and must not treat a syntactically valid proof as sufficient authorization to issue a credential.

`helper.DisableTlsVerification()` disables TLS certificate verification globally for the default HTTP transport. It is intended only for controlled development/test environments and must not be enabled in production.

## Interoperability

Some compatibility fields intentionally remain in the models for wallets that have not yet migrated completely to OpenID4VCI 1.0. Compatibility input should be normalized at the protocol boundary and the 1.0 representation should be used internally wherever possible.

When adding new protocol functionality, prefer the final OpenID4VCI 1.0 field names and structures instead of extending legacy Draft-based representations.

## Development

Run the test suite with:

```bash
go test ./...
```

Format changes before committing:

```bash
gofmt -w .
```

## License

See [LICENSE](LICENSE).
