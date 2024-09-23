package es.in2.vcverifier.config;

import es.in2.vcverifier.model.AuthorizationCodeData;
import es.in2.vcverifier.model.AuthorizationRequestJWT;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.TimeUnit;

@Configuration
@RequiredArgsConstructor
public class CacheStoreConfig {
    @Bean
    public CacheStore<AuthorizationRequestJWT> cacheStoreForAuthorizationRequestJWT() {
        return new CacheStore<>(10, TimeUnit.MINUTES);
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