package es.in2.vcverifier.model.credentials.dome;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

import java.util.List;
@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public record Mandate(
        @JsonProperty("id") String id,
        @JsonProperty("life_span") LifeSpan lifeSpan,
        @JsonProperty("mandatee") Mandatee mandatee,
        @JsonProperty("mandator") Mandator mandator,
        @JsonProperty("power") List<Power> power,
        @JsonProperty("signer") Signer signer
) {}
