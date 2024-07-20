package es.in2.verifier.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotNull;

public record AuthorizationResponse(
        @JsonProperty("vp_token") @NotNull String vpToken,
        @JsonProperty("presentation_submission") @NotNull String presentationSubmission
) {
}
