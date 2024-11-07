package es.in2.vcverifier.model.credentials.dome.machine;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import es.in2.vcverifier.model.credentials.Issuer;
import es.in2.vcverifier.model.credentials.dome.CredentialSubject;
import lombok.Builder;

import java.util.List;

@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public record LEARCredentialMachine(
        @JsonProperty("@context")
        List<String> context,
        @JsonProperty("id")
        String id,
        @JsonProperty("type")
        List<String> type,
        @JsonProperty("issuer")
        Issuer issuer,
        @JsonProperty("credentialSubject")
        CredentialSubject credentialSubject,
        @JsonProperty("validFrom")
        String validFrom,
        @JsonProperty("expirationDate")
        String expirationDate,
        @JsonProperty("issuanceDate")
        String issuanceDate
) {

}