package es.in2.verifier.domain.model.dto.credentials;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

@Builder
public record Contact(
        @JsonProperty("email") String email,
        @JsonProperty("phone") String mobilePhone
){}