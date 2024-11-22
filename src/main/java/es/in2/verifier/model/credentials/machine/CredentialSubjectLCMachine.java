package es.in2.verifier.model.credentials.machine;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

@Builder
public record CredentialSubjectLCMachine(
        @JsonProperty("mandate") MandateLCMachine mandate
) {}