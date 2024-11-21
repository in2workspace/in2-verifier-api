package es.in2.verifier.config.properties;

import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "crypto")
public record CryptoProperties(@NotNull String privateKey) {
}
