package es.in2.verifier.domain.model.dto.credentials.employee;


import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

@Builder
public record PowerLCEmployee(
        @JsonProperty("id") String id,
        @JsonProperty("tmf_action") Object tmfAction,
        @JsonProperty("tmf_domain") String tmfDomain,
        @JsonProperty("tmf_function") String tmfFunction,
        @JsonProperty("tmf_type") String tmfType
) {}