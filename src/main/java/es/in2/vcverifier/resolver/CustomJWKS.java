package es.in2.vcverifier.resolver;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

import java.util.List;

@Builder
public record CustomJWKS(
        @JsonProperty("keys") List<CustomJWK> keys
) {

    @Builder
    record CustomJWK(
            @JsonProperty("kty") String kty,
            @JsonProperty("crv") String crv,
            @JsonProperty("x") String x,
            @JsonProperty("y") String y,
            @JsonProperty("kid") String kid
    ) {
    }

}
