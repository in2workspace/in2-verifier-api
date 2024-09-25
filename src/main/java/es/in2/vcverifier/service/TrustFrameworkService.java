package es.in2.vcverifier.service;

public interface TrustFrameworkService {
    public String fetchAllowedClient();
    boolean isIssuerIdAllowed(String issuerId);
    boolean isParticipantIdAllowed(String participantId);
}
