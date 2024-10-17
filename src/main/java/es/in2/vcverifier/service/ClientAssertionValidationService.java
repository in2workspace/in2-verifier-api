package es.in2.vcverifier.service;

import com.nimbusds.jose.Payload;

public interface ClientAssertionValidationService {
    boolean validateClientAssertionJWTClaims(String clientId, Payload payload);
}
