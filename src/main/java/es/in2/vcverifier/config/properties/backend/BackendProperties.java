package es.in2.vcverifier.config.properties.backend;

import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.validation.annotation.Validated;

import java.util.List;
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
            @NestedConfigurationProperty TrustedIssuersListUrl trustedIssuersListUrl,
            @NestedConfigurationProperty TrustedServicesListUrl trustedServicesListUrl,
            @NestedConfigurationProperty RevokedCredentialListUrl revokedCredentialListUrl) {

        public TrustFramework(
                TrustedIssuersListUrl trustedIssuersListUrl,
                TrustedServicesListUrl trustedServicesListUrl,
                RevokedCredentialListUrl revokedCredentialListUrl) {
        // todo decide whether this should be optional
            this.trustedIssuersListUrl = Optional.ofNullable(trustedIssuersListUrl).orElse(new TrustedIssuersListUrl(""));
            this.trustedServicesListUrl = Optional.ofNullable(trustedServicesListUrl).orElse(new TrustedServicesListUrl(""));
            this.revokedCredentialListUrl = Optional.ofNullable(revokedCredentialListUrl).orElse(new RevokedCredentialListUrl(""));
        }
    }

    public record TrustedIssuersListUrl(String uri) {}
    public record TrustedServicesListUrl(String uri) {}
    public record RevokedCredentialListUrl(String uri) {}

    public TrustFramework getFirstTrustFramework() {
        return trustFrameworks.isEmpty() ? new TrustFramework(null, null, null) : trustFrameworks.get(0);
    }
}
