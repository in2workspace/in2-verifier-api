package es.in2.verifier.model.credentials.lear;

import es.in2.verifier.model.credentials.Issuer;

import java.util.List;

public interface LEARCredential {
    List<String> context();
    String id();
    List<String> type();
    Issuer issuer();
    String mandateeId();
    String mandatorOrganizationIdentifier();
    String validFrom();
    String validUntil();
}
