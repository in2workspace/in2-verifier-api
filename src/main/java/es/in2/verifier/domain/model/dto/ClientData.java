package es.in2.verifier.domain.model.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public record ClientData(
        String id,
        String url,
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