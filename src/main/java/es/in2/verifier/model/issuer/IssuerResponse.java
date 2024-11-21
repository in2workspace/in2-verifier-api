package es.in2.verifier.model.issuer;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

import java.util.List;

@Builder
public record IssuerResponse (
        @JsonProperty("did")
        String did,
        @JsonProperty("attributes")
        List<IssuerAttribute> attributes
){
}
