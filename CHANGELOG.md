# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v1.0.1]
### Fixed
- Fixed registration button link on the login qr page.


## [v1.0.0]
### Added
- Spring Security with Authorization Server configuration, supporting OIDC flows (OID4VP flow).
- Custom authentication filters to handle token requests and authorization code flows.
- Custom token filters for OIDC token validation and processing.
- Cryptographic components for ECKey generation (P-256) and managing cryptographic properties
- LoginQrController for generating and displaying a QR code to initiate authentication requests.
- Oid4vpController for handling authentication requests and responses for Verifiable Presentations (VPs).
- AuthorizationResponseProcessorService: Added service to supports the processing of the presentation submission in compliance with the OID4VP flow.
- ClientAssertionValidationService to validate JWT claims for client assertions.
- ResolverController for resolving Decentralized Identifiers (DIDs) to JWKs.
- DIDService to fetch public keys associated with Decentralized Identifiers (DIDs).
- JWTService for JWT generation, parsing, signature verification, and payload extraction.
- TrustFrameworkService for validating allowed clients, issuers, and participants within the trust framework.
- VpService for validate and extract credentials from Verifiable Presentations (VPs).
- JtiTokenCache. In-memory JTI token to track and prevent token reuse.
- CacheStore. Implemented cache management
- ClientLoaderConfig. Loads OAuth2 clients dynamically from a JSON file