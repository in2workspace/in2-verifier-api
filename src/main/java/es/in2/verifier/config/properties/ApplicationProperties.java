package es.in2.verifier.config.properties;

import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.ConstructorBinding;
import org.springframework.validation.annotation.Validated;

import java.util.Optional;
import java.util.concurrent.TimeUnit;

@Validated
@ConfigurationProperties(prefix = "api")
public record ApplicationProperties(
        @NotNull String externalDomain,
        @NotNull String clientId,
        @NotNull ApplicationPaths paths,
        @NotNull CacheStore cacheStore
) {

    @ConstructorBinding
    public ApplicationProperties(String externalDomain, String clientId, ApplicationPaths paths,
                                 CacheStore cacheStore) {
        this.externalDomain = externalDomain;
        this.clientId = clientId;
        this.paths = Optional.ofNullable(paths)
                .orElse(new ApplicationPaths("/api/v1/authentication_response"));
        this.cacheStore = Optional.ofNullable(cacheStore)
                .orElse(new CacheStore(10, TimeUnit.valueOf("MINUTES")));
    }

    public record ApplicationPaths(@NotNull String authenticationResponsePath) {
    }

    public record CacheStore(@NotNull int lifetime, @NotNull TimeUnit timeUnit) {
    }

}
