package es.in2.vcverifier.model.credentials.lear.employee;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import es.in2.vcverifier.model.credentials.VerifiableCredential;
import es.in2.vcverifier.model.credentials.lear.LifeSpan;
import es.in2.vcverifier.model.credentials.lear.Mandator;
import es.in2.vcverifier.model.credentials.lear.Power;
import es.in2.vcverifier.model.credentials.lear.Signer;
import lombok.Getter;
import lombok.experimental.SuperBuilder;
import lombok.extern.jackson.Jacksonized;

import java.util.List;

@Getter
@SuperBuilder
@Jacksonized
@JsonInclude(JsonInclude.Include.NON_NULL)
public class LEARCredentialEmployee extends VerifiableCredential {

    @JsonProperty("credentialSubject")
    private final CredentialSubject learCredentialSubject;
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record CredentialSubject(
            @JsonProperty("mandate") Mandate mandate
    ) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Mandate(
            @JsonProperty("id") String id,
            @JsonProperty("life_span") LifeSpan lifeSpan,
            @JsonProperty("mandatee") Mandatee mandatee,
            @JsonProperty("mandator") Mandator mandator,
            @JsonProperty("power") List<Power> power,
            @JsonProperty("signer") Signer signer
    ) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Mandatee(
            @JsonProperty("id") String id,
            @JsonProperty("email") String email,
            @JsonProperty("first_name") String firstName,
            @JsonProperty("last_name") String lastName,
            @JsonProperty("mobile_phone") String mobilePhone
    ) {}
}


