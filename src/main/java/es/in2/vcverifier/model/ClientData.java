package es.in2.vcverifier.model;

import java.util.List;

public record ClientData(
        String id,
        String clientId,
        String clientSecret,
        List<String> redirectUris,
        List<String> scopes,
        List<String> clientAuthenticationMethods,
        List<String> authorizationGrantTypes,
        Boolean requireAuthorizationConsent,
        List<String> postLogoutRedirectUris,
        Boolean requireProofKey,
        String jwkSetUrl,
        String tokenEndpointAuthenticationSigningAlgorithm
) {}