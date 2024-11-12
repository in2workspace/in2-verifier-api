package es.in2.vcverifier.model.credentials.employee;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

import java.util.List;

@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
public record LEARCredentialEmployee(
        @JsonProperty("@context") List<String> context,
        @JsonProperty("id") String id,
        @JsonProperty("type") List<String> type,
        @JsonProperty("credentialSubject") CredentialSubjectLCEmployee credentialSubject,
        @JsonProperty("expirationDate") String expirationDate,
        @JsonProperty("issuanceDate") String issuanceDate,
        @JsonProperty("issuer") String issuer,
        @JsonProperty("validFrom") String validFrom,
        @JsonProperty("validUntil") String validUntil
) {}