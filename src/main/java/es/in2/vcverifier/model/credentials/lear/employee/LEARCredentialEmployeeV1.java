package es.in2.vcverifier.model.credentials.lear.employee;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import es.in2.vcverifier.model.credentials.Issuer;
import es.in2.vcverifier.model.credentials.IssuerDeserializer;
import es.in2.vcverifier.model.credentials.lear.LEARCredential;
import es.in2.vcverifier.model.credentials.lear.employee.subject.CredentialSubjectV1;
import lombok.Builder;

import java.util.List;

@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public record LEARCredentialEmployeeV1(
        @JsonProperty("@context")
        List<String> context,
        @JsonProperty("id")
        String id,
        @JsonProperty("type")
        List<String> type,
        @JsonProperty("issuer") @JsonDeserialize(using = IssuerDeserializer.class)
        Issuer issuer,
        @JsonProperty("credentialSubject")
        CredentialSubjectV1 credentialSubject,
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

        public String mandateeFirstName(){
                return credentialSubject.mandate().mandatee().firstName();
        }

        public String mandateeLastName(){
                return credentialSubject.mandate().mandatee().lastName();
        }

        public String mandateeEmail(){
                return credentialSubject.mandate().mandatee().email();
        }

}
