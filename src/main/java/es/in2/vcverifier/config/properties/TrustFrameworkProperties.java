package es.in2.vcverifier.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.boot.context.properties.bind.ConstructorBinding;

import java.util.Optional;

@ConfigurationProperties(prefix = "trust-framework")
public record TrustFrameworkProperties(
        @NestedConfigurationProperty TrustedIssuerListProperties trustedIssuerList,
        @NestedConfigurationProperty ClientsRepositoryProperties clientsRepository,
        @NestedConfigurationProperty RevocationListProperties revocationList) {

    @ConstructorBinding
    public TrustFrameworkProperties(
            TrustedIssuerListProperties trustedIssuerList,
            ClientsRepositoryProperties clientsRepository,
            RevocationListProperties revocationList) {
        this.trustedIssuerList = Optional.ofNullable(trustedIssuerList).orElse(new TrustedIssuerListProperties(""));
        this.clientsRepository = Optional.ofNullable(clientsRepository).orElse(new ClientsRepositoryProperties(""));
        this.revocationList = Optional.ofNullable(revocationList).orElse(new RevocationListProperties(""));
    }

    public record TrustedIssuerListProperties(String uri) {
    }

    public record ClientsRepositoryProperties(String uri) {
    }

    public record RevocationListProperties(String uri) {
    }
}

