<div align="center">
  
  <h1>VC Verifier</h1>
  <span>by </span><a href="https://in2.es">in2.es</a>
  
  <p><p>
  
  [![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=in2workspace_in2-vc-verifier&metric=alert_status)](https://sonarcloud.io/dashboard?id=in2workspace_in2-vc-verifier)
  
  [![Bugs](https://sonarcloud.io/api/project_badges/measure?project=in2workspace_in2-vc-verifier&metric=bugs)](https://sonarcloud.io/summary/new_code?id=in2workspace_in2-vc-verifier)
  [![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=in2workspace_in2-vc-verifier&metric=vulnerabilities)](https://sonarcloud.io/dashboard?id=in2workspace_in2-vc-verifier)
  [![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=in2workspace_in2-vc-verifier&metric=security_rating)](https://sonarcloud.io/dashboard?id=in2workspace_in2-vc-verifier)
  [![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=in2workspace_in2-vc-verifier&metric=code_smells)](https://sonarcloud.io/summary/new_code?id=in2workspace_in2-vc-verifier)
  [![Lines of Code](https://sonarcloud.io/api/project_badges/measure?project=in2workspace_in2-vc-verifier&metric=ncloc)](https://sonarcloud.io/dashboard?id=in2workspace_in2-vc-verifier)
  
  [![Coverage](https://sonarcloud.io/api/project_badges/measure?project=in2workspace_in2-vc-verifier&metric=coverage)](https://sonarcloud.io/summary/new_code?id=in2workspace_in2-vc-verifier)
  [![Duplicated Lines (%)](https://sonarcloud.io/api/project_badges/measure?project=in2workspace_in2-vc-verifier&metric=duplicated_lines_density)](https://sonarcloud.io/summary/new_code?id=in2workspace_in2-vc-verifier)
  [![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=in2workspace_in2-vc-verifier&metric=reliability_rating)](https://sonarcloud.io/dashboard?id=in2workspace_in2-vc-verifier)
  [![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=in2workspace_in2-vc-verifier&metric=sqale_rating)](https://sonarcloud.io/dashboard?id=in2workspace_in2-vc-verifier)
  [![Technical Debt](https://sonarcloud.io/api/project_badges/measure?project=in2workspace_in2-vc-verifier&metric=sqale_index)](https://sonarcloud.io/summary/new_code?id=in2workspace_in2-vc-verifier)

</div>

# Introduction

Spring Authorization Server is a framework that provides implementations of the OAuth 2.1 and OpenID Connect 1.0 specifications and other related specifications. 
It is built on top of Spring Security to provide a secure, light-weight, 
and customizable foundation for building OpenID Connect 1.0 Identity Providers and OAuth2 Authorization Server products.

# Testing

We test the first call by sending a GET request to the '/oauth2/authorize' endpoint.

```text
http://localhost:9000/oauth2/authorize?response_type=code&client_id=did:key:wejkdew87fwhef9833f4&request_uri=https://dome-marketplace.org/api/v1/request.jwt%23GkurKxf5T0Y-mnPFCHqWOMiZi4VS138cQO_V7PZHAdM&state=af0ifjsldkj&nonce=n-0S6_WzA2Mj
```