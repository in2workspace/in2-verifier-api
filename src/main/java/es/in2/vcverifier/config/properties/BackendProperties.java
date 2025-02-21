package es.in2.vcverifier.config.properties;

import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.validation.annotation.Validated;

import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;

@Validated
@ConfigurationProperties(prefix = "verifier.backend")
public record BackendProperties(
        @NotNull String url,
        @NotNull @NestedConfigurationProperty Identity identity,
        @NotNull @NestedConfigurationProperty List<TrustFramework> trustFrameworks
) {
    public record Identity(@NotNull String privateKey) {}

    public record TrustFramework(
            @NotNull String name,
            @NestedConfigurationProperty TrustedIssuersListUrl trustedIssuersListUrl,
            @NestedConfigurationProperty TrustedServicesListUrl trustedServicesListUrl,
            @NestedConfigurationProperty RevokedCredentialListUrl revokedCredentialListUrl) {

        public TrustFramework(
                String name,
                TrustedIssuersListUrl trustedIssuersListUrl,
                TrustedServicesListUrl trustedServicesListUrl,
                RevokedCredentialListUrl revokedCredentialListUrl) {
            this.name = Optional.ofNullable(name).orElse("");
            this.trustedIssuersListUrl = Optional.ofNullable(trustedIssuersListUrl).orElse(new TrustedIssuersListUrl(""));
            this.trustedServicesListUrl = Optional.ofNullable(trustedServicesListUrl).orElse(new TrustedServicesListUrl(""));
            this.revokedCredentialListUrl = Optional.ofNullable(revokedCredentialListUrl).orElse(new RevokedCredentialListUrl(""));
        }
    }

    public record TrustedIssuersListUrl(String uri) {}
    public record TrustedServicesListUrl(String uri) {}
    public record RevokedCredentialListUrl(String uri) {}

    //todo this is temporary while VCVerifier can only manage one trustframework
    public TrustFramework getDOMETrustFrameworkByName() {
        return trustFrameworks.stream()
                .filter(tf -> tf.name().equalsIgnoreCase("DOME"))
                .findFirst()
                .orElseThrow(() -> new NoSuchElementException("No TrustFramework found with name 'DOME'"));
    }

}
