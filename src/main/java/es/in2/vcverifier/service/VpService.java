package es.in2.vcverifier.service;

import com.fasterxml.jackson.databind.JsonNode;

public interface VpService {
    boolean validateVerifiablePresentation(String verifiablePresentation);
    Object getCredentialFromTheVerifiablePresentation(String verifiablePresentation);
    JsonNode getCredentialFromTheVerifiablePresentationAsJsonNode(String verifiablePresentation);
}
