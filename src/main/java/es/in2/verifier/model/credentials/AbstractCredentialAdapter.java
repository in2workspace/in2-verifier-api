package es.in2.verifier.model.credentials;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.verifier.exception.JsonConversionException;

import java.util.List;

public abstract class AbstractCredentialAdapter<T> implements VerifiableCredential {

    protected final T credential;

    protected AbstractCredentialAdapter(Object credential, ObjectMapper objectMapper, Class<T> clazz) {
        try {
            this.credential = objectMapper.convertValue(credential, clazz);
        } catch (IllegalArgumentException e) {
            throw new JsonConversionException("Error deserializing " + clazz.getSimpleName() + ": " + e);
        }
    }

    @Override
    public List<String> getContext() {
        return getCredentialContext();
    }

    @Override
    public String getId() {
        return getCredentialId();
    }

    @Override
    public List<String> getType() {
        return getCredentialType();
    }

    @Override
    public String getIssuer() {
        return getCredentialIssuer();
    }

    @Override
    public String getValidFrom() {
        return getCredentialValidFrom();
    }

    @Override
    public String getValidUntil() {
        return getCredentialValidUntil();
    }

    @Override
    public String getMandateeId() {
        return getCredentialMandateeId();
    }

    @Override
    public String getMandatorOrganizationIdentifier() {
        return getCredentialMandatorOrganizationIdentifier();
    }

    @Override
    public T getCredential() {
        return credential;
    }

    // Abstract methods to be implemented by subclasses
    protected abstract List<String> getCredentialContext();
    protected abstract String getCredentialId();
    protected abstract List<String> getCredentialType();
    protected abstract String getCredentialIssuer();
    protected abstract String getCredentialValidFrom();
    protected abstract String getCredentialValidUntil();
    protected abstract String getCredentialMandateeId();
    protected abstract String getCredentialMandatorOrganizationIdentifier();
}

