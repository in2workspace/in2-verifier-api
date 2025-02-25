package es.in2.vcverifier.config.properties;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.validation.annotation.Validated;

import java.util.List;
import java.util.NoSuchElementException;

@Validated
@ConfigurationProperties(prefix = "verifier.backend")
public record BackendProperties(
        @NotNull String url,
        @NotNull @NestedConfigurationProperty Identity identity,
        @NotNull @Valid List<TrustFramework> trustFrameworks
) {
    public record Identity(@NotNull String privateKey) {}

    public record TrustFramework(
            @NotNull String name,
            @NotNull @Valid @NestedConfigurationProperty TrustedIssuersListUrl trustedIssuersListUrl,
            @NotNull @Valid @NestedConfigurationProperty TrustedServicesListUrl trustedServicesListUrl,
            @NotNull @Valid @NestedConfigurationProperty RevokedCredentialListUrl revokedCredentialListUrl
    ) {}

    public record TrustedIssuersListUrl(@NotNull String uri) {}
    public record TrustedServicesListUrl(@NotNull String uri) {}
    public record RevokedCredentialListUrl(@NotNull String uri) {}

    //todo this is temporary while VCVerifier can only manage one trustframework
    public TrustFramework getDOMETrustFrameworkByName() {
        return trustFrameworks.stream()
                .filter(tf -> tf.name().equalsIgnoreCase("DOME"))
                .findFirst()
                .orElseThrow(() -> new NoSuchElementException("No TrustFramework found with name 'DOME'"));
    }

}
