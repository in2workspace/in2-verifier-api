package es.in2.vcverifier.model.credentials.machine;

import com.fasterxml.jackson.annotation.JsonProperty;
import es.in2.vcverifier.model.credentials.Contact;
import lombok.Builder;

@Builder
public record MandateeLCMachine(
        @JsonProperty("id") String id,
        @JsonProperty("serviceName") String serviceName,
        @JsonProperty("serviceType") String serviceType,
        @JsonProperty("version") String version,
        @JsonProperty("domain") String domain,
        @JsonProperty("ipAddress") String ipAddress,
        @JsonProperty("description") String description,
        @JsonProperty("contact") Contact contact
) {}
