package es.in2.verifier.model.credentials.dome.machine;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.verifier.model.credentials.AbstractCredentialAdapter;

import java.util.List;

public class MachineCredentialAdapter extends AbstractCredentialAdapter<LEARCredentialMachine> {

    public MachineCredentialAdapter(Object credential, ObjectMapper objectMapper) {
        super(credential, objectMapper, LEARCredentialMachine.class);
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
        return credential.issuer().id();
    }

    @Override
    protected String getCredentialValidFrom() {
        return credential.validFrom();
    }

    @Override
    protected String getCredentialValidUntil() {
        return credential.validUntil();
    }

    @Override
    protected String getCredentialMandateeId() {
        return credential.credentialSubject().mandate().mandatee().id();
    }

    @Override
    protected String getCredentialMandatorOrganizationIdentifier() {
        return credential.credentialSubject().mandate().mandator().organizationIdentifier();
    }
}

