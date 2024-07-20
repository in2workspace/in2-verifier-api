package es.in2.verifier.model;

import lombok.Builder;

@Builder
public record QrResponse(
        String qrCode
) {
}
