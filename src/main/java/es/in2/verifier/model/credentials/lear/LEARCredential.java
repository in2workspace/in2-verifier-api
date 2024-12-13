package es.in2.verifier.model.credentials.lear;

import java.util.List;

public interface LEARCredential {
    List<String> context();
    String id();
    List<String> type();
    String issuerId(); // Adjusted to be common
    String mandateeId();
    String mandatorOrganizationIdentifier();
    String validFrom();
    String validUntil();
}
