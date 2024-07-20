package es.in2.verifier.config;

import es.in2.verifier.config.properties.ApplicationProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;

import java.util.concurrent.TimeUnit;

@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {

    private final ApplicationProperties applicationProperties;

    public String getExternalDomain() {
        return applicationProperties.externalDomain();
    }

    public String getClientId() {
        return applicationProperties.clientId();
    }

    public String getAuthorizationResponsePath() {
        return applicationProperties.paths().authenticationResponsePath();
    }

    public int getCacheLifetime() {
        return applicationProperties.cacheStore().lifetime();
    }

    public TimeUnit getCacheTimeUnit() {
        return applicationProperties.cacheStore().timeUnit();
    }

}
