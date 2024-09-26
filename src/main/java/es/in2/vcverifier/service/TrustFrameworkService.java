package es.in2.vcverifier.service;

public interface TrustFrameworkService {
    String fetchAllowedClient();
    boolean isIssuerIdAllowed(String issuerId);
    boolean isParticipantIdAllowed(String participantId);
}
