package es.in2.verifier.domain.model.enums;

import lombok.Getter;

@Getter
public enum LEARCredentialType {

    LEAR_CREDENTIAL_EMPLOYEE("LEARCredentialEmployee"),
    LEAR_CREDENTIAL_MACHINE("LEARCredentialMachine");

    private final String value;

    LEARCredentialType(String value) {
        this.value = value;
    }

}
