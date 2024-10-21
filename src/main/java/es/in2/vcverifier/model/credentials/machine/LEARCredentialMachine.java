package es.in2.vcverifier.model.credentials.machine;

import com.fasterxml.jackson.annotation.JsonProperty;
import es.in2.vcverifier.model.credentials.Issuer;
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
        @JsonProperty("credentialSubject") CredentialSubjectLCMachine credentialSubject
) {}