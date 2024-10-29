package es.in2.vcverifier.model;

import com.fasterxml.jackson.databind.JsonNode;
import lombok.Builder;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;

@Builder
public record AuthorizationCodeData(
        String state,
        JsonNode verifiableCredential,
        OAuth2Authorization oAuth2Authorization,
        String clientNonce

) {
}
