package es.in2.vcverifier.model;

import lombok.Builder;

@Builder
public record AuthenticationRequestClientData (
        String redirectUri
){
}
