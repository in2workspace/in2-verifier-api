package es.in2.verifier.config.properties;

import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "flags")
public record FlagsProperties(@NotNull boolean isNonceRequiredOnFapiProfile) {
}
