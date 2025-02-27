package es.in2.vcverifier.config.properties;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import org.hibernate.validator.constraints.URL;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.List;
import java.util.NoSuchElementException;

@Validated
@ConfigurationProperties(prefix = "verifier.backend")
public record BackendProperties(
        @NotNull @URL String url,
        @NotNull Identity identity,
        @NotNull @Valid List<TrustFramework> trustFrameworks // Spring Boot ho converteix automàticament
) {

    public record Identity(@NotNull String privateKey) {}

    public record TrustFramework(
            @NotNull String name,
            @NotNull @URL String trustedIssuersListUrl,
            @NotNull @URL String trustedServicesListUrl,
            @NotNull @URL String revokedCredentialListUrl
    ) {}

    // TODO: Això és temporal mentre VCVerifier només pot gestionar un trustFramework
    public TrustFramework getDOMETrustFrameworkByName() {
        return trustFrameworks.stream()
                .filter(tf -> tf.name().equalsIgnoreCase("DOME"))
                .findFirst()
                .orElseThrow(() -> new NoSuchElementException("No TrustFramework found with name 'DOME'"));
    }
}
