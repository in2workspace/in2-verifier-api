package es.in2.vcverifier.model.credentials.lear.machine;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record Contact(
        @JsonProperty("email") String email,
        @JsonProperty("phone") String mobilePhone
) {}

