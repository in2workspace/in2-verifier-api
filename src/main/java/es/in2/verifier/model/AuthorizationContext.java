package es.in2.verifier.model;

import lombok.Builder;

@Builder
public record AuthorizationContext(
        String state,
        String scope,
        String redirectUri,
        String clientNonce,
        String originalRequestURL,
        String requestUri
) {
}
