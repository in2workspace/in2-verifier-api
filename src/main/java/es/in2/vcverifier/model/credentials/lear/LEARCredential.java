package es.in2.vcverifier.model.credentials.lear;

import es.in2.vcverifier.model.credentials.Issuer;

import java.util.List;

public interface LEARCredential {
    List<String> context();
    String id();
    List<String> type();
    Issuer issuer(); // Adjusted to be common
    String mandateeId();
    String mandatorOrganizationIdentifier();
    String validFrom();
    String validUntil();
}
