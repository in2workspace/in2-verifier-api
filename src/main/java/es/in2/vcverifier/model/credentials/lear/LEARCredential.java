package es.in2.vcverifier.model.credentials.lear;

import es.in2.vcverifier.model.credentials.Issuer;

import java.util.List;

public interface LEARCredential {
    List<String> getContext();
    String getId();
    List<String> getType();
    Issuer getIssuer(); // Adjusted to be common
    String getMandateeId();
    String getMandatorOrganizationIdentifier();
    String getValidFrom();
    String getValidUntil();
}
