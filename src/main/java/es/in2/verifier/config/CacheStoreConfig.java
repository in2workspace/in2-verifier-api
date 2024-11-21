package es.in2.verifier.config;

import es.in2.verifier.config.properties.SecurityProperties;
import es.in2.verifier.model.AuthorizationCodeData;
import es.in2.verifier.model.AuthorizationRequestJWT;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import java.time.temporal.ChronoUnit;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.TimeUnit;

@Configuration
@RequiredArgsConstructor
public class CacheStoreConfig {

    private final SecurityProperties securityProperties;
    @Bean
    public CacheStore<AuthorizationRequestJWT> cacheStoreForAuthorizationRequestJWT() {
        return new CacheStore<>(
                Long.parseLong(securityProperties.loginCode().expirationProperties().expiration()),
                TimeUnit.of(ChronoUnit.valueOf(securityProperties.token().accessToken().cronUnit())));
    }

    @Bean
    public CacheStore<OAuth2AuthorizationRequest> cacheStoreForOAuth2AuthorizationRequest() {
        return new CacheStore<>(10, TimeUnit.MINUTES);
    }

    @Bean
    public CacheStore<AuthorizationCodeData> cacheStoreForAuthorizationCodeData() {
        return new CacheStore<>(10, TimeUnit.MINUTES);
    }

    @Bean
    public Set<String> jtiCache() {
        return new HashSet<>();
    }

}
