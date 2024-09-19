package es.in2.vcverifier.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.nimbusds.jose.Payload;

public interface VpService {
    boolean validateVerifiablePresentation(String verifiablePresentation);
    JsonNode getCredentialFromTheVerifiablePresentation(String verifiablePresentation);
}
