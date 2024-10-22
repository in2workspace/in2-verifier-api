package es.in2.vcverifier.model.credentials.employee;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

@Builder
public record MandateeLCEmployee(
        @JsonProperty("id") String id,
        @JsonProperty("email") String email,
        @JsonProperty("first_name") String firstName,
        @JsonProperty("last_name") String lastName,
        @JsonProperty("mobile_phone") String mobilePhone
) {}