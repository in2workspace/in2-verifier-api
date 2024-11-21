package es.in2.verifier.model;

import lombok.Builder;

@Builder
public record AuthorizationRequestJWT(String authRequest) {
}
