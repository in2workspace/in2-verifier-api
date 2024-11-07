package es.in2.vcverifier.model.credentials.dome.employee;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.vcverifier.exception.JsonConversionException;
import es.in2.vcverifier.model.credentials.VerifiableCredential;

import java.util.List;

public class EmployeeCredentialAdapter implements VerifiableCredential {

    private final LEARCredentialEmployee credential;

    public EmployeeCredentialAdapter(Object credential, ObjectMapper objectMapper) {
        try {
            this.credential = objectMapper.convertValue(credential, LEARCredentialEmployee.class);
        } catch (IllegalArgumentException e) {
            throw new JsonConversionException("Error deserializing LEARCredentialEmployee: " + e);
        }
    }

    @Override
    public List<String> getContext() {
        return credential.context();
    }

    @Override
    public String getId() {
        return credential.id();
    }

    @Override
    public List<String> getType() {
        return credential.type();
    }

    @Override
    public String getIssuer() {
        return credential.issuer();
    }

    @Override
    public String getValidFrom() {
        return credential.validFrom();
    }

    @Override
    public String getExpirationDate() {
        return credential.expirationDate();
    }

    @Override
    public String getIssuanceDate() {
        return credential.issuanceDate();
    }

    public String getMandateeId() {
        return credential.credentialSubject().mandate().mandatee().id();
    }

    public String getMandatorOrganizationIdentifier() {
        return credential.credentialSubject().mandate().mandator().organizationIdentifier();
    }
    public String getMandateeFirstName() {
        return credential.credentialSubject().mandate().mandatee().firstName();
    }
    public String getMandateeLastName() {
        return credential.credentialSubject().mandate().mandatee().lastName();
    }
    public String getMandateeEmail() {
        return credential.credentialSubject().mandate().mandatee().email();
    }


}
