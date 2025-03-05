package es.in2.vcverifier.model.credentials.lear.employee;

import es.in2.vcverifier.model.credentials.lear.LEARCredential;

public interface LEARCredentialEmployee extends LEARCredential {
    String getMandateeFirstName();
    String getMandateeLastName();
    String getMandateeEmail();
}
