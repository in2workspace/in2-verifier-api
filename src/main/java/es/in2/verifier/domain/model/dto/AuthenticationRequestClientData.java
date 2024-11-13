package es.in2.verifier.domain.model.dto;

import lombok.Builder;

@Builder
public record AuthenticationRequestClientData (
        String redirectUri,
        String clientId
){
}
