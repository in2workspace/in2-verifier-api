package es.in2.vcverifier.model.credentials.lear.machine;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import es.in2.vcverifier.model.credentials.Issuer;
import es.in2.vcverifier.model.credentials.IssuerDeserializer;
import es.in2.vcverifier.model.credentials.lear.LEARCredential;
import es.in2.vcverifier.model.credentials.lear.machine.subject.CredentialSubject;
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
        @JsonProperty("issuer") @JsonDeserialize(using = IssuerDeserializer.class)
        Issuer issuer,
        @JsonProperty("credentialSubjectV2")
        CredentialSubject credentialSubject,
        @JsonProperty("validFrom")
        String validFrom,
        @JsonProperty("validUntil")
        String validUntil,
        @JsonProperty("expirationDate")
        String expirationDate,
        @JsonProperty("issuanceDate")
        String issuanceDate
) implements LEARCredential {

    @Override
    public String mandateeId() {
        return credentialSubject.mandate().mandatee().id();
    }

    @Override
    public String mandatorOrganizationIdentifier() {
        return credentialSubject.mandate().mandator().organizationIdentifier();
    }

}
