package es.in2.verifier.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

@JsonIgnoreProperties
public record RevokedCredentialIds (
        @JsonProperty("revoked_credentials")
        List<String> revokedCredentials
){
}
