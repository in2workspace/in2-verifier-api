package es.in2.vcverifier.config.properties;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.hibernate.validator.constraints.URL;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.List;
import java.util.NoSuchElementException;

@Validated
@ConfigurationProperties(prefix = "verifier.backend")
public record BackendProperties(
        @NotBlank @URL String url,
        @NotNull Identity identity,
        @NotNull @Valid List<TrustFramework> trustFrameworks
) {

    public record Identity(@NotBlank String privateKey) {}

    public record TrustFramework(
            @NotBlank String name,
            @NotBlank @URL String trustedIssuersListUrl,
            @NotBlank @URL String trustedServicesListUrl,
            @NotBlank @URL String revokedCredentialListUrl
    ) {}

    // TODO: this is temporary while VCVerifier can handle only one trustFramework
    public TrustFramework getDOMETrustFrameworkByName() {
        return trustFrameworks.stream()
                .filter(tf -> tf.name().equalsIgnoreCase("DOME"))
                .findFirst()
                .orElseThrow(() -> new NoSuchElementException("No TrustFramework found with name 'DOME'"));
    }
}
