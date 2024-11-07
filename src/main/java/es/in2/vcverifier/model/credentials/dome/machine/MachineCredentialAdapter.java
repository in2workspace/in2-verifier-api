package es.in2.vcverifier.model.credentials.dome.machine;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.vcverifier.exception.JsonConversionException;
import es.in2.vcverifier.model.credentials.VerifiableCredential;

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
}
