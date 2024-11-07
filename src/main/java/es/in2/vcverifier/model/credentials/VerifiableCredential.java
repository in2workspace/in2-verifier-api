package es.in2.vcverifier.model.credentials;

import java.util.List;

public interface VerifiableCredential {

    List<String> getContext();
    String getId();
    List<String> getType();
    String getIssuer();
    String getValidFrom();
    String getExpirationDate();
    String getIssuanceDate();
}


