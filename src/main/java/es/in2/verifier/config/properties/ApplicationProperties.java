package es.in2.verifier.config.properties;

import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.ConstructorBinding;
import org.springframework.validation.annotation.Validated;

import java.util.Optional;

@Validated
@ConfigurationProperties(prefix = "api")
public record ApplicationProperties(
        @NotNull String externalDomain,
        @NotNull String clientId,
        @NotNull ApplicationPaths paths
) {

    @ConstructorBinding
    public ApplicationProperties(String externalDomain, String clientId, ApplicationPaths paths) {
        this.externalDomain = externalDomain;
        this.clientId = clientId;
        this.paths = Optional.ofNullable(paths).orElse(new ApplicationPaths(""));
    }

    public record ApplicationPaths(@NotNull String authenticationResponsePath) {
    }
}
