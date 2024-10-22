package es.in2.vcverifier.model.issuer;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

@Builder
public record IssuerAttribute(
        @JsonProperty("hash")
        String hash,
        @JsonProperty("body")
        String body,
        @JsonProperty("issuerType")
        String issuerType
) {
}
