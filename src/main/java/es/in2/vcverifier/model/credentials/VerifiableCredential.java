package es.in2.vcverifier.model.credentials;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.experimental.SuperBuilder;

import java.util.List;
import java.util.Map;

@Getter
@SuperBuilder
@JsonInclude(JsonInclude.Include.NON_NULL)
public abstract class VerifiableCredential {

    // Getters and setters
    @JsonProperty("@context")
    protected List<String> context;
    protected String id;
    protected List<String> type;
    protected String name;
    protected String description;
    protected String issuer;
    protected Map<String, Object> issuerObject;
    protected Map<String, Object> credentialSubject;
    protected String validFrom;
    protected String validUntil;
    protected Map<String, Object> status;
    protected Map<String, Object> credentialSchema;
    protected Map<String, Object> refreshService;
    protected Map<String, Object> termsOfUse;
    protected Map<String, Object> evidence;

}


