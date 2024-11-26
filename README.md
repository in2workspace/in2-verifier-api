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

Spring Authorization Server is a framework that provides implementations of the OAuth 2.1 and OpenID Connect 1.0 specifications and other related specifications. 
It is built on top of Spring Security to provide a secure, light-weight, 
and customizable foundation for building OpenID Connect 1.0 Identity Providers and OAuth2 Authorization Server products.

# Configuring the Verifier as an External Identity Provider on Keycloak

This guide will teach you how to configure an external Identity Provider using **OpenID Connect v1.0**. The guide is divided into two main sections:

1. **Registering the Client with the Identity Provider (IDP)**
2. **Configuring the External Identity Provider in Keycloak**

Images and links to documentation are included to simplify the process.

---

## Section 1: Registering the Client on the DOME Trust Framework

Before configuring Keycloak, you need to register your client in the DOME trust framework. This step is essential for integrating the client with the verifier.

### Important Note

Some of the required information for this registration (such as **Redirect URIs** or **Public Keys**) will need to be obtained from your Keycloak configuration. These steps are detailed in **Section 2: Configuring the External Identity Provider in Keycloak**. It is recommended to complete those specific steps first:

1. Configure the necessary keys in Keycloak under **Realm Settings > Keys**.
2. Obtain the **Redirect URIs** required for the Identity Provider.

Once you have this information, proceed with the steps below.

---

### Steps to Register the Client:

The registration process involves following specific steps detailed in the Trust Framework documentation. Please refer to the following guide for comprehensive instructions:

**[How to Insert your client in the Trusted Lists](https://github.com/DOME-Marketplace/trust-framework/blob/main/README.md#how-to-insert-a-new-value-in-the-trusted-lists)**

This guide will walk you through:
- Adding a new client.
- Configuring required attributes.

Be sure to complete all the steps outlined in the documentation after obtaining the necessary information from Keycloak.

---

## Section 2: Configuring the Verifier as an External Identity Provider in Keycloak

### Step 1: Add a New Provider for ECDSA Keys

Access **Realm Settings** → **Keys** → **Add Providers**, and add a new provider of type **ecdsa-generated** with elliptic curve **P-256**.
<div style="border: 1px solid #ddd; padding: 10px; border-radius: 5px; background: #f9f9f9;">
    <img src="docs/images/add-key-provider.png" alt="ECDSA Provider Configuration">
</div>

---

### Step 2: Create the Identity Provider in Keycloak

1. Navigate to the **Identity Providers** section and add a new provider of type **OpenID Connect v1.0**.
   <div style="border: 1px solid #ddd; padding: 10px; border-radius: 5px; background: #f9f9f9;">
       <img src="docs/images/add-oidc-provider.png" alt="Adding OpenID Connect Provider">
   </div>

#### Configuring OpenID Connect v1.0

Complete the following fields:

#### Primary Attributes

| Attribute                  | Description                                                                                        |
|----------------------------|----------------------------------------------------------------------------------------------------|
| **Alias**                  | A name to identify the Identity Provider.                                                          |
| **Use discovery endpoint** | Recommended if the Identity Provider provides a Discovery Endpoint to avoid manual configurations. |
| **Discovery endpoint**     | The endpoint where the IDP's data can be found.                                                    |

Here is an example of the configuration:
<div style="border: 1px solid #ddd; padding: 10px; border-radius: 5px; background: #f9f9f9;">
    <img src="docs/images/primary-attributes.png" alt="Configuring Primary Attributes">
</div>

#### Client Authentication

- **Client Authentication:** Select `JWT signed with private key`.
- **Client ID:** The client identifier you registered with the IDP (e.g., `in2-issuer`).
- **Client Secret:** Not needed since we will use `JWT signed with private key`.
- **Client Assertion Signature Algorithm:** Select `ES256`, which is supported by the IDP we are configuring.
- **Client Assertion Audience:** Use the equivalent of the issuer obtained in the discovery.

<div style="border: 1px solid #ddd; padding: 10px; border-radius: 5px; background: #f9f9f9;">
    <img src="docs/images/client-configuration.png" alt="Configuring Client Authentication">
</div>

---

### Step 3: Configure Advanced Settings

Now, we will configure the advanced settings needed for this integration:

1. Go to **Advanced settings**:
   - **Access Token is JWT:** Set to `On`.
   - **Trust Email:** Set to `On`.
    <div style="border: 1px solid #ddd; padding: 10px; border-radius: 5px; background: #f9f9f9;">
        <img src="docs/images/advanced-settings.png" alt="Advanced Settings - Access Token and Trust Email">
    </div>

2. Go to **OpenID Connect settings > Advanced**:
   - **Disable user info:** Set to `On`.
   - **Disable nonce:** Set to `On`.
   - **Scopes:** Add `learcredential profile email`.

     Including **profile** and **email** in the scopes ensures that the **ID Token** contains the basic user information required to create a user in Keycloak. This includes details such as the user's name and email address, which are essential for creating a basic user profile.

    <div style="border: 1px solid #ddd; padding: 10px; border-radius: 5px; background: #f9f9f9;">
        <img src="docs/images/advanced.png" alt="OpenID Connect Settings - Advanced Configuration">
    </div>

---

### Step 4: Configure the Mappers

Mappers allow you to extract information from the IDP and use it for local users. The following types will be used:

#### 4.1. Attribute Importer

- **Claim:** The location of the value to retrieve, e.g., `vc.credentialSubject.mandate.mandator.organizationIdentifier`.
- **User Attribute Name:** The user attribute to which the retrieved value will be associated, e.g., `organizationIdentifier`.

<div style="border: 1px solid #ddd; padding: 10px; border-radius: 5px; background: #f9f9f9;">
    <img src="docs/images/attribute-importer.png" alt="Attribute Importer Configuration">
</div>

#### 4.2. Hardcoded Attribute

- **User Attribute:** The attribute to which you want to assign a default value.
- **User Attribute Value:** The desired value.

<div style="border: 1px solid #ddd; padding: 10px; border-radius: 5px; background: #f9f9f9;">
    <img src="docs/images/hardcoded-attribute-importer.png" alt="Hardcoded Attribute Configuration">
</div>

#### 4.3. Username Template Importer

- **Template:** Use the claim `${CLAIM.email}` to extract the email sent by the IDP.
- **Target:** Specify the target field as `BROKER_ID`.

This ensures the link between the user and their Verifiable Credential (VC) is based on the email rather than the `sub` of the ID Token, allowing a user to have multiple VCs associated.

<div style="border: 1px solid #ddd; padding: 10px; border-radius: 5px; background: #f9f9f9;">
    <img src="docs/images/username-template-importer.png" alt="Username Template Importer Configuration">
</div>

#### 4.4. Sync Mode Override

- **Import:** Adds data only during the user's first login. This is the most common use case.
- **Force:** Overwrites data with each login. Useful if a user has multiple credentials for different purposes and wants to use the one they select during login.

---

> **Reminder:** Registering the client with the IDP is a critical step for integration to work correctly. Ensure you have completed all the steps.