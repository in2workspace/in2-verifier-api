package es.in2.vcverifier.model.credentials.lear.machine;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import es.in2.vcverifier.model.credentials.VerifiableCredential;
import es.in2.vcverifier.model.credentials.lear.LifeSpan;
import es.in2.vcverifier.model.credentials.lear.Mandator;
import es.in2.vcverifier.model.credentials.lear.Power;
import es.in2.vcverifier.model.credentials.lear.Signer;
import lombok.Getter;
import lombok.experimental.SuperBuilder;

import java.util.List;

@Getter
@SuperBuilder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class LEARCredentialMachine extends VerifiableCredential {

    @JsonProperty("credentialSubject")
    private CredentialSubject credentialSubject;

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
            @JsonProperty("serviceName") String serviceName,
            @JsonProperty("serviceType") String serviceType,
            @JsonProperty("version") String version,
            @JsonProperty("domain") String domain,
            @JsonProperty("ipAddress") String ipAddress,
            @JsonProperty("description") String description,
            @JsonProperty("contact") Contact contact
    ) {}
}

