package es.in2.verifier.model.issuer;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

import java.util.List;

@Builder
public record IssuerCredentialsCapabilities (
        @JsonProperty("validFor") TimeRange validFor,
        @JsonProperty("credentialsType") String credentialsType,
        @JsonProperty("claims") List<Claim> claims
){
}
