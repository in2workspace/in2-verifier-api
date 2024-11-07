package es.in2.vcverifier.model.credentials.dome;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public record Signer(
        @JsonProperty("commonName") String commonName,
        @JsonProperty("country") String country,
        @JsonProperty("emailAddress") String emailAddress,
        @JsonProperty("organization") String organization,
        @JsonProperty("organizationIdentifier") String organizationIdentifier,
        @JsonProperty("serialNumber") String serialNumber
) {}
