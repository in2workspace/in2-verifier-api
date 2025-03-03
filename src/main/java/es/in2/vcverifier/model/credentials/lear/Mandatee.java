package es.in2.vcverifier.model.credentials.lear;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import es.in2.vcverifier.model.credentials.lear.machine.Contact;
import lombok.Builder;

@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public record Mandatee(
        @JsonProperty("id") String id,
        @JsonProperty("email") String email,
        @JsonProperty("first_name") String firstName,
        @JsonProperty("last_name") String lastName,
        @JsonProperty("mobile_phone") String mobilePhone,
        @JsonProperty("serviceName") String serviceName,
        @JsonProperty("serviceType") String serviceType,
        @JsonProperty("version") String version,
        @JsonProperty("domain") String domain,
        @JsonProperty("ipAddress") String ipAddress,
        @JsonProperty("description") String description,
        @JsonProperty("contact") Contact contact
) {}
