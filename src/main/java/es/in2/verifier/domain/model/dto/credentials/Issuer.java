package es.in2.verifier.domain.model.dto.credentials;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

@Builder
public record Issuer(
        @JsonProperty("id")String id
) { }