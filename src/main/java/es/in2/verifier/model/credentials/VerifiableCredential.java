package es.in2.verifier.model.credentials;

import java.util.List;

public interface VerifiableCredential {

    List<String> getContext();
    String getId();
    List<String> getType();
    String getIssuer();
    String getValidFrom();
    String getValidUntil();
    String getMandateeId();
    String getMandatorOrganizationIdentifier();
    Object getCredential();

}


