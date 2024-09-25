package es.in2.vcverifier.model.credentials.machine;

import com.fasterxml.jackson.annotation.JsonProperty;
import es.in2.vcverifier.model.credentials.LifeSpan;
import es.in2.vcverifier.model.credentials.Mandator;
import es.in2.vcverifier.model.credentials.Signer;
import lombok.Builder;

import java.util.List;
@Builder
public record MandateLCMachine(
        @JsonProperty("id") String id,
        @JsonProperty("life_span") LifeSpan lifeSpan,
        @JsonProperty("mandatee") MandateeLCMachine mandateeLCMachine,
        @JsonProperty("mandator") Mandator mandator,
        @JsonProperty("power") List<PowerLCMachine> powerLCMachine,
        @JsonProperty("signer") Signer signer
) {}
