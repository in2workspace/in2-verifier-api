package es.in2.verifier.domain.model.dto.credentials.employee;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

@Builder
public record CredentialSubjectLCEmployee(@JsonProperty("mandate") MandateLCEmployee mandate) {
}