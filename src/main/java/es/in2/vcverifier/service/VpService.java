package es.in2.vcverifier.service;

import com.fasterxml.jackson.databind.JsonNode;

public interface VpService {
    boolean validateVerifiablePresentation(String verifiablePresentation, String state);
    Object getCredentialFromTheVerifiablePresentation(String verifiablePresentation);
    JsonNode getCredentialFromTheVerifiablePresentationAsJsonNode(String verifiablePresentation, String state);
}
