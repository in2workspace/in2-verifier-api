package es.in2.vcverifier.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

import java.util.List;

@Builder
public record LEARCredentialMachine(
        @JsonProperty("@context") List<String> context,
        @JsonProperty("id") String id,
        @JsonProperty("type") List<String> type,
        @JsonProperty("issuer") Issuer issuer,
        @JsonProperty("issuanceDate") String issuanceDate,
        @JsonProperty("validFrom") String validFrom,
        @JsonProperty("expirationDate") String expirationDate,
        @JsonProperty("credentialSubject") CredentialSubject credentialSubject
) {

    @Builder
    public record Issuer(@JsonProperty("id")String id) {
    }

    @Builder
    public record CredentialSubject(
            @JsonProperty("mandate") Mandate mandate
    ) {
        @Builder
        public record Mandate(
                @JsonProperty("id") String id,
                @JsonProperty("life_span") LifeSpan lifeSpan,
                @JsonProperty("mandatee") Mandatee mandatee,
                @JsonProperty("mandator") Mandator mandator,
                @JsonProperty("power") List<Power> power,
                @JsonProperty("signer") Signer signer
        ) {
            @Builder
            public record LifeSpan(
                    @JsonProperty("startDateTime") String startDateTime,
                    @JsonProperty("endDateTime") String endDateTime
            ) {}
            @Builder
            public record Mandatee(
                    @JsonProperty("id") String id,
                    @JsonProperty("serviceName") String serviceName,
                    @JsonProperty("serviceType") String serviceType,
                    @JsonProperty("version") String version,
                    @JsonProperty("domain") String domain,
                    @JsonProperty("ipAddress") String ipAddress,
                    @JsonProperty("description") String description,
                    @JsonProperty("contact") Contact contact
            ) {}

            @Builder
            public record Contact(
                    @JsonProperty("email") String email,
                    @JsonProperty("phone") String mobilePhone
            ){}

            @Builder
            public record Mandator(
                    @JsonProperty("commonName") String commonName,
                    @JsonProperty("country") String country,
                    @JsonProperty("emailAddress") String emailAddress,
                    @JsonProperty("organization") String organization,
                    @JsonProperty("organizationIdentifier") String organizationIdentifier,
                    @JsonProperty("serialNumber") String serialNumber
            ) {}
            @Builder

            public record Power(
                    @JsonProperty("id") String id,
                    @JsonProperty("domain") String domain,
                    @JsonProperty("function") String function,
                    @JsonProperty("action") String action
            ) {}

            @Builder
            public record Signer(
                    @JsonProperty("commonName") String commonName,
                    @JsonProperty("country") String country,
                    @JsonProperty("emailAddress") String emailAddress,
                    @JsonProperty("organization") String organization,
                    @JsonProperty("organizationIdentifier") String organizationIdentifier,
                    @JsonProperty("serialNumber") String serialNumber
            ) {}
        }
    }
}