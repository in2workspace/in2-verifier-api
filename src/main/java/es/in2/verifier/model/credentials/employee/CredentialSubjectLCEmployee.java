package es.in2.verifier.model.credentials.employee;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

@Builder
public record CredentialSubjectLCEmployee(@JsonProperty("mandate") MandateLCEmployee mandate) {
}