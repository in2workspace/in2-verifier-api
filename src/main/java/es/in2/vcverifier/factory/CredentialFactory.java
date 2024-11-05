package es.in2.vcverifier.factory;

import es.in2.vcverifier.model.VerifiableCredential;

import java.util.Map;

public interface CredentialFactory {
    VerifiableCredential createCredential(String subjectId, Map<String, Object> payload);
}
