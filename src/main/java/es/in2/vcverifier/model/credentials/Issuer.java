package es.in2.vcverifier.model.credentials;

import com.fasterxml.jackson.annotation.JsonProperty;

public interface Issuer {

    @JsonProperty("id")
    String getId();
}
