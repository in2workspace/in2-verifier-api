package es.in2.verifier.domain.service;

import java.util.Map;

public interface CertificateValidationService {
    void extractAndVerifyCertificate(String verifiableCredential, Map<String, Object> vcHeader, String expectedOrgId);
}
