<div align="center">
  <h1>IN2 Verifier API</h1>
  <span>by </span><a href="https://in2.es">in2.es</a>
  <p><p>

  [![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=in2workspace_in2-verifier-api&metric=alert_status)](https://sonarcloud.io/dashboard?id=in2workspace_in2-verifier-api)

  [![Bugs](https://sonarcloud.io/api/project_badges/measure?project=in2workspace_in2-verifier-api&metric=bugs)](https://sonarcloud.io/summary/new_code?id=in2workspace_in2-verifier-api)
  [![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=in2workspace_in2-verifier-api&metric=vulnerabilities)](https://sonarcloud.io/dashboard?id=in2workspace_in2-verifier-api)
  [![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=in2workspace_in2-verifier-api&metric=security_rating)](https://sonarcloud.io/dashboard?id=in2workspace_in2-verifier-api)
  [![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=in2workspace_in2-verifier-api&metric=code_smells)](https://sonarcloud.io/summary/new_code?id=in2workspace_in2-verifier-api)
  [![Lines of Code](https://sonarcloud.io/api/project_badges/measure?project=in2workspace_in2-verifier-api&metric=ncloc)](https://sonarcloud.io/dashboard?id=in2workspace_in2-verifier-api)
  
  [![Coverage](https://sonarcloud.io/api/project_badges/measure?project=in2workspace_in2-verifier-api&metric=coverage)](https://sonarcloud.io/summary/new_code?id=in2workspace_in2-verifier-api)
  [![Duplicated Lines (%)](https://sonarcloud.io/api/project_badges/measure?project=in2workspace_in2-verifier-api&metric=duplicated_lines_density)](https://sonarcloud.io/summary/new_code?id=in2workspace_in2-verifier-api)
  [![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=in2workspace_in2-verifier-api&metric=reliability_rating)](https://sonarcloud.io/dashboard?id=in2workspace_in2-verifier-api)
  [![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=in2workspace_in2-verifier-api&metric=sqale_rating)](https://sonarcloud.io/dashboard?id=in2workspace_in2-verifier-api)
  [![Technical Debt](https://sonarcloud.io/api/project_badges/measure?project=in2workspace_in2-verifier-api&metric=sqale_index)](https://sonarcloud.io/summary/new_code?id=in2workspace_in2-verifier-api)
</div>

# Introduction

Spring Authentication Server is a framework that provides implementations of the **OAuth 2.0** and **OpenID Connect 1.0** specifications, as well as other related standards.  
It is built on top of **Spring Security** to provide a secure, lightweight, and customizable foundation for building **OpenID Connect 1.0 Identity Providers** and **OAuth 2 Authentication Server** products.

Our **Verifier** builds upon this robust foundation, extending it with additional functionalities from **OpenID Connect Core** and **OpenID for Verifiable Presentations (OpenID4VP)**.

This enhancement enables the Verifier to support authentication workflows between clients and users based on **Verifiable Credentials (VCs)**. By combining these standards, the Verifier creates a robust and secure system for managing digital identities, allowing users to authenticate seamlessly while ensuring the integrity and verifiability of their credentials.

With the Verifier, organizations can leverage:
- **OpenID Connect Core** for traditional client-user authentication.
- **OpenID4VP** for presenting and validating tamper-proof digital credentials.  
  This unique combination positions the Verifier as a versatile and modern solution for both centralized and decentralized authentication scenarios.


## Verifier Interaction Methods

The verifier interacts with clients in two ways:

1. **Using OpenID Connect Core**  
   OpenID Connect Core serves as the primary standard for authentication and Authentication between clients and the verifier.  
   [Learn more about OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)

2. **Using OpenID for Verifiable Presentations (OpenID4VP)**  
   OpenID4VP enables the verifier to process verifiable presentations (VPs) containing verifiable credentials (VCs) during authentication flows.  
   [Learn more about OpenID4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0-20.html)

---

# OpenID Connect Integration

## Client Authentication Flow

The OpenID Connect integration for clients consists of two main steps:

1. **Authentication Request**
2. **Token Request**

### Step 1: Client Registration

To interact with the verifier, a client must be registered in the verifier's client list.  
Currently, the **[DOME Trust Framework GitHub repository](https://github.com/DOME-Marketplace/trust-framework.git)** is used to manage the client registry.

#### Approaches for Registering Clients

There are two approaches for registering clients, depending on the needs and capabilities of the client application:

1. **Using `did:key` (Required for FAPI Profile)**  
   This approach is mandatory for clients that need to use the **Financial-grade API (FAPI)** profile of OpenID Connect.
    - **Client ID**: Use your `did:key` as the `clientId`.
    - **JWK Set URL**: Use the verifier's endpoint in the format:
      ```
      https://<domain>/oidc/did/<did:key:...>
      ```
      This endpoint allows the verifier to reconstruct the public key from the `did:key` for signature validation.
    - **Why Use `did:key`?**: This ensures compliance with FAPI requirements, offering enhanced security and interoperability by eliminating the need for a separate JWKS endpoint.

2. **Using a Unique Identifier (For Non-FAPI Clients)**  
   This approach is suitable for clients that do not require FAPI compliance or cannot support it, such as Keycloak acting as a broker.
    - **Client ID**: Use a unique identifier that clearly defines the purpose of the client (e.g., `issuer-dome`).
    - **JWK Set URL**: Provide the URL where your public keys are exposed for validation.
    - **Why Use a Unique Identifier?**: This method provides flexibility for clients that do not require the strict security guarantees of FAPI but still need to integrate securely with the verifier.

---

#### Which data is needed to set a new entry into the Trusted Services List?

The trusted services list contains all the verified and authorized services within the DOME ecosystem. These services have met the required standards for secure and trusted interactions. To add a new entry to the trusted services list, specific information must be provided in a YAML file, adhering to the structure outlined below:

| **Field**                                       | **Description**                                                                                                                                                                                                                                                                            |
|-------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **clientId**                                    | Should be a `did:key` or a unique identifier for your client. Using a `did:key` allows the verifier to obtain your public keys for signature verification without needing a separate JWKS endpoint.                                                                                        |
| **url**                                         | The base URL of your service or application.                                                                                                                                                                                                                                               |
| **redirectUris**                                | Must include all the URLs where you expect to receive authentication responses. These should be HTTPS URLs to ensure secure communication.                                                                                                                                                 |
| **scopes**                                      | Currently, only `openid_learcredential` is accepted. This scope allows your service to request the necessary credentials.                                                                                                                                                                  |
| **clientAuthenticationMethods**                 | Must be set to `["client_secret_jwt"]`, as this is the only supported authentication method.                                                                                                                                                                                               |
| **authorizationGrantTypes**                     | Must be set to `["authorization_code"]`, as this is the only supported grant type.                                                                                                                                                                                                         |
| **postLogoutRedirectUris**                      | Include URLs where users should be redirected after they log out from your service.                                                                                                                                                                                                        |
| **requireAuthorizationConsent**                 | Set to `false` because explicit user consent is not required in this flow.                                                                                                                                                                                                                 |
| **requireProofKey**                             | Set to `false` as PKCE is not utilized.                                                                                                                                                                                                                                                    |
| **jwkSetUrl**                                   | If you're using a `did:key` for your `clientId`, you do not need to provide a `jwkSetUrl` because the verifier can derive your JWKS directly from the `did:key`. However, if you're not using a unique identifier, you must provide the `jwkSetUrl` where your public keys can be fetched. |
| **tokenEndpointAuthenticationSigningAlgorithm** | Must be set to `ES256`, as this is the only supported algorithm.                                                                                                                                                                                                                           |

---

#### How to add the client to the Trusted Services List

Once the necessary data is collected, you can proceed to submit a Pull Request (PR) to the **[DOME Trust Framework GitHub repository](https://github.com/DOME-Marketplace/trust-framework.git)** to add the new client to the Trusted Services List. The repository serves as the central place for managing trusted clients within the **DOME** ecosystem.

Follow these steps to submit the PR:
1. Fork the **[DOME Trust Framework GitHub repository](https://github.com/DOME-Marketplace/trust-framework.git)**.
2. Add the new client entry (in YAML format) to the `clients` section.
3. Submit the PR for review and approval.

Once the PR is merged, the new client will be added to the trusted services list and will be able to interact with the verifier.

---

#### Example YAML Entry

Below is an example of how to define a client in the trusted services list:

```yaml
clients:
  - clientId: "did:key:zDnaeypyWjzn54GuUP7PmDXiiggCyiG7ksMF7Unm7kjtEKBez"
    url: "https://dome-marketplace-sbx.org"
    redirectUris: ["https://dome-marketplace-sbx.org/auth/vc/callback"]
    scopes: ["openid_learcredential"]
    clientAuthenticationMethods: ["client_secret_jwt"]
    authorizationGrantTypes: ["authorization_code"]
    postLogoutRedirectUris: ["https://dome-marketplace-sbx.org/"]
    requireAuthorizationConsent: false
    requireProofKey: false
    jwkSetUrl: "https://verifier.dome-marketplace-sbx.org/oidc/did/did:key:zDnaeypyWjzn54GuUP7PmDXiiggCyiG7ksMF7Unm7kjtEKBez"
    tokenEndpointAuthenticationSigningAlgorithm: "ES256"
```

---

### Step 2: Authentication and Token Requests

Once the client is registered, the authentication flow proceeds as follows:

1. **Authentication Request**
    - The client sends an Authentication request to the verifier.
    - The verifier authenticates the user, presenting a login screen where the user must use their wallet to provide a valid credential.
    - This process utilizes the **OpenID4VP flow**, where the user presents their verifiable credential (VC) to authenticate.
    - If the authentication is successful, the verifier sends an **authentication response** to the client's redirection URL (`redirect_uri`).

2. **Token Request**
    - After receiving the authentication response, the client submits a token request to the verifier.
    - The client includes its **Client Assertion JWT**, which the verifier uses to validate the request's origin and integrity.
    - If validated, the verifier issues a **token response**, containing the necessary information for the client to authenticate the user within their platform.

---

## Supported Scopes

The verifier currently supports the following scopes:

1. **Mandatory Scope**:
    - `openid learcredential` this scope is required for authentication and for accessing the user's credential data.

2. **Optional Scopes**:
    - `profile`
    - `email`

Including the optional scopes ensures that the **ID Token** contains basic user information such as the user's name and email address. This facilitates integration with other Identity Providers.
> **Note:** The optional scopes (`profile` and `email`) must always be used in combination with the `learcredential` scope.

---

## Token Response Data Model

When a client requests a token with the scopes `openid learcredential profile email`, the **token response** will include the following fields:

### Example Token Response

```
{
"access_token": "eyJra...",
"id_token": "eyJra.....",
"token_type": "Bearer",
"expires_in": 18000
}
```