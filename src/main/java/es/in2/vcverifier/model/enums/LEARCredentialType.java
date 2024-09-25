package es.in2.vcverifier.model.enums;

import lombok.Getter;

@Getter
public enum LEARCredentialType {

    LEARCredentialEmployee("LEARCredentialEmployee"),
    LEARCredentialMachine("LEARCredentialMachine");

    private final String value;

    LEARCredentialType(String value) {
        this.value = value;
    }
}
