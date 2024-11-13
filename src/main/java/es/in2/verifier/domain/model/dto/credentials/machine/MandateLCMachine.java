package es.in2.verifier.domain.model.dto.credentials.machine;

import com.fasterxml.jackson.annotation.JsonProperty;
import es.in2.verifier.domain.model.dto.credentials.LifeSpan;
import es.in2.verifier.domain.model.dto.credentials.Mandator;
import es.in2.verifier.domain.model.dto.credentials.Signer;
import lombok.Builder;

import java.util.List;
@Builder
public record MandateLCMachine(
        @JsonProperty("id") String id,
        @JsonProperty("life_span") LifeSpan lifeSpan,
        @JsonProperty("mandatee") MandateeLCMachine mandatee,
        @JsonProperty("mandator") Mandator mandator,
        @JsonProperty("power") List<PowerLCMachine> power,
        @JsonProperty("signer") Signer signer
) {}
