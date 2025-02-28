package es.in2.verifier.model.credentials;

import com.fasterxml.jackson.annotation.JsonProperty;

public interface Issuer {

    @JsonProperty("id")
    String getId();
}

