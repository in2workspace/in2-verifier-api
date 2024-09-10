package es.in2.vcverifier.model;

import lombok.Getter;

import java.util.List;
    @Getter
    public class ClientData {
        private String id;
        private String clientId;
        private List<String> redirectUris;
        private List<String> scopes;
        private List<String> clientAuthenticationMethods;
        private List<String> authorizationGrantTypes;
        private boolean requireAuthorizationConsent;

        // Getters y setters

        public void setId(String id) {
            this.id = id;
        }

        public void setClientId(String clientId) {
            this.clientId = clientId;
        }

        public void setRedirectUris(List<String> redirectUris) {
            this.redirectUris = redirectUris;
        }

        public void setScopes(List<String> scopes) {
            this.scopes = scopes;
        }

        public void setClientAuthenticationMethods(List<String> clientAuthenticationMethods) {
            this.clientAuthenticationMethods = clientAuthenticationMethods;
        }

        public void setAuthorizationGrantTypes(List<String> authorizationGrantTypes) {
            this.authorizationGrantTypes = authorizationGrantTypes;
        }

        public void setRequireAuthorizationConsent(boolean requireAuthorizationConsent) {
            this.requireAuthorizationConsent = requireAuthorizationConsent;
        }
    }
