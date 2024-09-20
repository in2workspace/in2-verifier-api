package es.in2.vcverifier.model;

import com.fasterxml.jackson.databind.JsonNode;
import lombok.Builder;

@Builder
public record AuthorizationCodeData(
        String state,
        String clientId,
        JsonNode verifiableCredential
) {
}
