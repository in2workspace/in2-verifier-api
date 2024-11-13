package es.in2.verifier.domain.model.dto.credentials.machine;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

@Builder
public record PowerLCMachine(
        @JsonProperty("id") String id,
        @JsonProperty("domain") String domain,
        @JsonProperty("function") String function,
        @JsonProperty("action") String action
) {}
