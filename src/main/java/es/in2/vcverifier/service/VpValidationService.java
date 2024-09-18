package es.in2.vcverifier.service;

import com.nimbusds.jose.Payload;

public interface VpValidationService {
    boolean validateJWTClaims(String clientId, Payload payload);
    boolean validateVerifiablePresentation(String verifiablePresentation);
}
