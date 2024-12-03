package es.in2.verifier.model.credentials.dome.employee;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.verifier.exception.JsonConversionException;
import es.in2.verifier.model.credentials.VerifiableCredential;

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
    public String getValidUntil() {return credential.expirationDate();
    }
    @Override
    public String getMandateeId() {
        return credential.credentialSubject().mandate().mandatee().id();
    }

    @Override
    public String getMandatorOrganizationIdentifier() {
        return credential.credentialSubject().mandate().mandator().organizationIdentifier();
    }
    @Override
    public LEARCredentialEmployee getCredential() {
        return credential;
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
