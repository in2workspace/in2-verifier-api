package es.in2.vcverifier.model;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

    @Getter
    @Setter
    public class ClientData {
        private String id;
        private String clientId;
        private String clientSecret;
        private List<String> redirectUris;
        private List<String> scopes;
        private List<String> clientAuthenticationMethods;
        private List<String> authorizationGrantTypes;
        private Boolean requireAuthorizationConsent;
        private List<String> postLogoutRedirectUris;
        private Boolean requireProofKey;
        private String jwkSetUrl;
        private String tokenEndpointAuthenticationSigningAlgorithm;
    }
