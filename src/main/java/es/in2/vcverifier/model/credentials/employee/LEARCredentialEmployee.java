package es.in2.vcverifier.model.credentials.employee;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

import java.util.List;

@Builder
public record LEARCredentialEmployee(
        @JsonProperty("@context") List<String> context,
        @JsonProperty("id") String id,
        @JsonProperty("type") List<String> type,
        @JsonProperty("credentialSubject") CredentialSubjectLCEmployee credentialSubjectLCEmployee,
        @JsonProperty("expirationDate") String expirationDate,
        @JsonProperty("issuanceDate") String issuanceDate,
        @JsonProperty("issuer") String issuer,
        @JsonProperty("validFrom") String validFrom
) {}