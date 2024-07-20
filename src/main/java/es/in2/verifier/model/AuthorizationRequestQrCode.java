package es.in2.verifier.model;

import lombok.Builder;

@Builder
public record AuthorizationRequestQrCode(
        String qrCode
) {
}
