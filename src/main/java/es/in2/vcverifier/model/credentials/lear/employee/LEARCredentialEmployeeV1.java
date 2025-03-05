package es.in2.vcverifier.model.credentials.lear.employee;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import es.in2.vcverifier.model.credentials.Issuer;
import es.in2.vcverifier.model.credentials.IssuerDeserializer;
import es.in2.vcverifier.model.credentials.lear.employee.subject.CredentialSubjectV1;
import lombok.Builder;

import java.util.List;

@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public record LEARCredentialEmployeeV1(
        @JsonProperty("@context")
        List<String> getContext,
        @JsonProperty("id")
        String getId,
        @JsonProperty("type")
        List<String> getType,
        @JsonProperty("issuer") @JsonDeserialize(using = IssuerDeserializer.class)
        Issuer getIssuer,
        @JsonProperty("credentialSubject")
        CredentialSubjectV1 credentialSubjectV1,
        @JsonProperty("validFrom")
        String getValidFrom,
        @JsonProperty("validUntil")
        String getValidUntil,
        @JsonProperty("expirationDate")
        String expirationDate,
        @JsonProperty("issuanceDate")
        String issuanceDate
) implements LEARCredentialEmployee {

        @Override
        public String getMandateeId() {
                return credentialSubjectV1.mandate().mandatee().id();
        }

        @Override
        public String getMandatorOrganizationIdentifier() {
                return credentialSubjectV1.mandate().mandator().organizationIdentifier();
        }


        @Override
        public String getMandateeFirstName() {
                return credentialSubjectV1.mandate().mandatee().firstName();
        }

        @Override
        public String getMandateeLastName() {
                return credentialSubjectV1.mandate().mandatee().lastName();
        }

        @Override
        public String getMandateeEmail() {
                return credentialSubjectV1.mandate().mandatee().email();
        }
}
