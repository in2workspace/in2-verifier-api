package es.in2.vcverifier.config.properties.backend;

import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.validation.annotation.Validated;

import java.util.Optional;

@Validated
@ConfigurationProperties(prefix = "verifier.backend")
public record BackendProperties(
        @NotNull String url,
        @NotNull @NestedConfigurationProperty Identity identity,
        @NotNull @NestedConfigurationProperty TrustFramework trustFramework
) {
    public record Identity(@NotNull String privateKey) {}

    // waiting for TF properties to be defined as Required or Optional
    public record TrustFramework(
            @NestedConfigurationProperty TrustedIssuerList trustedIssuerList,
            @NestedConfigurationProperty ClientsRepository clientsRepository,
            @NestedConfigurationProperty RevocationList revocationList) {

        public TrustFramework(
                TrustedIssuerList trustedIssuerList,
                ClientsRepository clientsRepository,
                RevocationList revocationList) {
            this.trustedIssuerList = Optional.ofNullable(trustedIssuerList).orElse(new TrustedIssuerList(""));
            this.clientsRepository = Optional.ofNullable(clientsRepository).orElse(new ClientsRepository(""));
            this.revocationList = Optional.ofNullable(revocationList).orElse(new RevocationList(""));
        }
    }

    public record TrustedIssuerList(String uri) {}
    public record ClientsRepository(String uri) {}
    public record RevocationList(String uri) {}
}


