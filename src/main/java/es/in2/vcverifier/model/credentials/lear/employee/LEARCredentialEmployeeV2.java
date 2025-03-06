package es.in2.vcverifier.model.credentials.lear.employee;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import es.in2.vcverifier.model.credentials.Issuer;
import es.in2.vcverifier.model.credentials.IssuerDeserializer;
import es.in2.vcverifier.model.credentials.lear.employee.subject.CredentialSubjectV2;
import lombok.Builder;

import java.util.List;

@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public record LEARCredentialEmployeeV2(
        @JsonProperty("@context")
        List<String> context,
        @JsonProperty("id")
        String getId,
        @JsonProperty("type")
        List<String> getType,
        @JsonProperty("description")
        String description,
        @JsonProperty("issuer") @JsonDeserialize(using = IssuerDeserializer.class)
        Issuer getIssuer,
        @JsonProperty("credentialSubject")
        CredentialSubjectV2 credentialSubjectV2,
        @JsonProperty("validFrom")
        String getValidFrom,
        @JsonProperty("validUntil")
        String getValidUntil
) implements LEARCredentialEmployee {

    @Override
    public List<String> getContext() {
        return context;
    }

    @Override
    public String getMandateeId() {
        return credentialSubjectV2.mandate().mandatee().id();
    }

    @Override
    public String getMandatorOrganizationIdentifier() {
        return credentialSubjectV2.mandate().mandator().organizationIdentifier();
    }

    @Override
    public String getMandateeFirstName() {
        return credentialSubjectV2.mandate().mandatee().firstName();
    }

    @Override
    public String getMandateeLastName() {
        return credentialSubjectV2.mandate().mandatee().lastName();
    }

    @Override
    public String getMandateeEmail() {
        return credentialSubjectV2.mandate().mandatee().email();
    }
}
