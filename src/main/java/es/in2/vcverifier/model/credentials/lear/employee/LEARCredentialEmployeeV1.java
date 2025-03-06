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
) implements LEARCredentialEmployee {

        @Override
        public List<String> getContext() {
                return context;
        }

        @Override
        public String getId() {
                return id;
        }

        @Override
        public List<String> getType() {
                return type;
        }

        @Override
        public Issuer getIssuer() {
                return issuer;
        }

        @Override
        public String getMandateeId() {
                return credentialSubject.mandate().mandatee().id();
        }

        @Override
        public String getMandatorOrganizationIdentifier() {
                return credentialSubject.mandate().mandator().organizationIdentifier();
        }

        @Override
        public String getValidFrom() {
                return validFrom;
        }

        @Override
        public String getValidUntil() {
                return validUntil;
        }


        @Override
        public String getMandateeFirstName() {
                return credentialSubject.mandate().mandatee().firstName();
        }

        @Override
        public String getMandateeLastName() {
                return credentialSubject.mandate().mandatee().lastName();
        }

        @Override
        public String getMandateeEmail() {
                return credentialSubject.mandate().mandatee().email();
        }
}
