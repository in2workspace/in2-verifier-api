<h1>IN2 Verifier API</h1>

# Introduction

This solution implements a mechanism on top of OAuth 2.0 to request and present Verifiable Credentials as Verifiable Presentations.

As the primary extension, the protocol OpenID for Verifiable Presentations introduces the VP Token as a container to enable End-Users to present Verifiable Presentations to Verifiers using the Wallet. A VP Token contains one or more Verifiable Presentations in the same or different Credential formats.

# Premises
- Credentials of multiple formats can be presented in the same transaction.
- Implements same-device and cross-device scenarios.
- 

# Technical Decisions

Although we understand that the Verifier should implement several data models (W3C Verifiable Credentials Data Model, ISO mdoc, IETF SD-JWT VC, and AnonCreds), we decided to start with the W3C Verifiable Credentials Data Model [VC_DATA, v1.1](https://www.w3.org/TR/vc-data-model/) because it is the most widely used data model for Verifiable Credentials.

# Prerequisites

# Installation

To build the Docker image, run the following command:

```bash
docker build -t in2-verifier-api .
```

You could skip tests by running the following command:

```bash
docker build -t in2-verifier-api --build-arg SKIP_TESTS=true .
```

# Configuration

# Usage

You could run the Docker image by running the following command:

```bash
docker run -p 8080:8080 in2-verifier-api
```

Add '-d' to run the Docker image in detached mode:

```bash
docker run -d -p 8080:8080 in2-verifier-api
```

# API

# License

# Contributing

# Acknowledgements

# References
- [OpenID for Verifiable Credentials - Overview](https://openid.net/sg/openid4vc/)
- [OpenID for Verifiable Presentations - Editor's draft, 18 July 2024](https://openid.github.io/OpenID4VP/openid-4-verifiable-presentations-wg-draft.html)
- [Choosing between Spring Web or Webflux](https://andreibaptista.medium.com/choosing-between-spring-web-or-webflux-7aeb2167122f)
- [Spring Security OAuth Authorization Server](https://www.baeldung.com/spring-security-oauth-auth-server)
- [Static Content in Spring WebFlux](https://www.baeldung.com/spring-webflux-static-content)
- [Documenting a Spring REST API Using OpenAPI 3.0](https://www.baeldung.com/spring-rest-openapi-documentation)
