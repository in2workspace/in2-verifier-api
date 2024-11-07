package es.in2.vcverifier.model.credentials.dome;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public record Power(
        @JsonProperty("id") String id,
        @JsonProperty("tmf_action") Object tmfAction,
        @JsonProperty("tmf_domain") String tmfDomain,
        @JsonProperty("tmf_function") String tmfFunction,
        @JsonProperty("tmf_type") String tmfType
) {}

