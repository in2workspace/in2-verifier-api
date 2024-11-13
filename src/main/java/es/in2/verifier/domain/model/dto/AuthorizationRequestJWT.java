package es.in2.verifier.domain.model.dto;

import lombok.Builder;

@Builder
public record AuthorizationRequestJWT(String authRequest) {
}
