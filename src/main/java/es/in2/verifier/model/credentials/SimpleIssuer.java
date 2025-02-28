package es.in2.verifier.model.credentials;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
public record SimpleIssuer(@JsonProperty("id") String id) implements Issuer {
    @Override
    public String getId() {
        return id;
    }
}
