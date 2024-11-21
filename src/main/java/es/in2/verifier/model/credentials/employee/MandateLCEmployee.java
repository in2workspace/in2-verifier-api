package es.in2.verifier.model.credentials.employee;

import com.fasterxml.jackson.annotation.JsonProperty;
import es.in2.verifier.model.credentials.LifeSpan;
import es.in2.verifier.model.credentials.Mandator;
import es.in2.verifier.model.credentials.Signer;
import lombok.Builder;

import java.util.List;

@Builder
public record MandateLCEmployee(
        @JsonProperty("id") String id,
        @JsonProperty("life_span") LifeSpan lifeSpan,
        @JsonProperty("mandatee") MandateeLCEmployee mandatee,
        @JsonProperty("mandator") Mandator mandator,
        @JsonProperty("power") List<PowerLCEmployee> power,
        @JsonProperty("signer") Signer signer
) {}