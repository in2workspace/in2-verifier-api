package es.in2.verifier.model.credentials.dome.machine;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.verifier.exception.JsonConversionException;
import es.in2.verifier.model.credentials.VerifiableCredential;

import java.util.List;

public class MachineCredentialAdapter implements VerifiableCredential {

    private final LEARCredentialMachine credential;

    public MachineCredentialAdapter(Object credential, ObjectMapper objectMapper) {
        try {
            this.credential = objectMapper.convertValue(credential, LEARCredentialMachine.class);
        } catch (IllegalArgumentException e) {
            throw new JsonConversionException("Error deserializing LEARCredentialMachine: " + e);
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
        return credential.issuer().id();
    }

    @Override
    public String getValidFrom() {
        return credential.validFrom();
    }

    @Override
    public String getValidUntil() {
        return credential.validUntil();
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
    public LEARCredentialMachine getCredential() {
        return credential;
    }
}
