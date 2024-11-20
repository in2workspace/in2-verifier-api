# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v1.0.10](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.0.9)
### Fixed
- Add an error page for errors during the client authentication request.

## [v1.0.9](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.0.9)
### Fixed
- Fix images url
- Fix spacing between navbar and content for tablets width range

## [v1.0.8](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.0.8)
### Fixed
- Fix color contrast 
- Use brand colors, font and favicon
- Fix layout responsiveness

## [v1.0.7](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.0.7)
### Fixed
- Fix the JWKS endpoint response to use the claim `use` with `sig` value.

## [v1.0.6](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.0.6)
### Fixed
- Authentication request fix to comply with the OpenID Connect Core standard.

## [v1.0.5](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.0.5)
### Fixed
- Token response fix to comply with the OpenID Connect Core standard.

## [v1.0.4](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.0.4)
### Fixed
- Fix security issue with the signature verification.

## [v1.0.3](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.0.3)
### Added
- Support for OpenID Connect.
  - Only uses Authentication using the Authorization Code Flow (without PKCE).
  - Only uses Claims with Requesting Claims using Scope Values (openid learcredential)
  - Only uses Passing Request Parameters as JWTs (Passing a Request Object by Reference).
  - Only use Client Authentication method with Private Key JWT.
  - Only uses for P-256 ECDSA keys for Signing Access Token.
- Support for OpenID for Verifiable Presentations (OID4VP).
  - Implement VP Proof of Possession verification.
  - Implement Issuers, Participants and Services verification against the DOME Trust Framework.
  - Implement VC verification against the DOME Revoked Credentials List.
- Support FAPI
  - Only use request_uri as a REQUIRED claim in the Authentication Request Object.
- Implement DOME Human-To-Machine (H2M) authentication.
  - Implement Login page with QR code.
- Implement DOME Machine-To-Machine (M2M) authentication.
- Integrate with the DOME Trust Framework.

### Fixed
- Fix the issue with Login page not showing Wallet URL.
- Fix the issue with Login page not valid Registration URL.
- Fix the issue with Login page not redirecting to the Relying Party after expiration of the QR code.