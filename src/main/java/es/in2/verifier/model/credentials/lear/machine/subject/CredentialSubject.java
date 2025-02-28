package es.in2.verifier.model.credentials.lear.machine.subject;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import es.in2.verifier.model.credentials.lear.machine.subject.mandate.Mandate;
import lombok.Builder;

@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public record CredentialSubject(
        @JsonProperty("mandate") Mandate mandate
) {}
