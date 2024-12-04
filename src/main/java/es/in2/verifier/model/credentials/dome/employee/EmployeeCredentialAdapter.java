package es.in2.verifier.model.credentials.dome.employee;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.verifier.model.credentials.AbstractCredentialAdapter;

import java.util.List;

public class EmployeeCredentialAdapter extends AbstractCredentialAdapter<LEARCredentialEmployee> {

    public EmployeeCredentialAdapter(Object credential, ObjectMapper objectMapper) {
        super(credential, objectMapper, LEARCredentialEmployee.class);
    }

    @Override
    protected List<String> getCredentialContext() {
        return credential.context();
    }

    @Override
    protected String getCredentialId() {
        return credential.id();
    }

    @Override
    protected List<String> getCredentialType() {
        return credential.type();
    }

    @Override
    protected String getCredentialIssuer() {
        return credential.issuer();
    }

    @Override
    protected String getCredentialValidFrom() {
        return credential.validFrom();
    }

    @Override
    protected String getCredentialValidUntil() {
        return credential.expirationDate();
    }

    @Override
    protected String getCredentialMandateeId() {
        return credential.credentialSubject().mandate().mandatee().id();
    }

    @Override
    protected String getCredentialMandatorOrganizationIdentifier() {
        return credential.credentialSubject().mandate().mandator().organizationIdentifier();
    }

    // Additional methods specific to EmployeeCredentialAdapter
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

