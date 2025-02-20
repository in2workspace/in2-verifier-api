package es.in2.vcverifier.config;

import static es.in2.vcverifier.util.Constants.LOGIN_TIMEOUT;
import static es.in2.vcverifier.util.Constants.ACCESS_TOKEN_EXPIRATION_TIME;
import static es.in2.vcverifier.util.Constants.ID_TOKEN_EXPIRATION_TIME;

import es.in2.vcverifier.config.backend.BackendConfig;
import es.in2.vcverifier.config.properties.SecurityProperties;
import es.in2.vcverifier.model.AuthorizationCodeData;
import es.in2.vcverifier.model.AuthorizationRequestJWT;
import es.in2.vcverifier.model.RefreshTokenDataCache;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.TimeUnit;

@Configuration
@RequiredArgsConstructor
public class CacheStoreConfig {

    @Bean
    public CacheStore<AuthorizationRequestJWT> cacheStoreForAuthorizationRequestJWT() {
        return new CacheStore<>(
                Long.parseLong(LOGIN_TIMEOUT),
                TimeUnit.of(ChronoUnit.valueOf(securityProperties.token().accessToken().cronUnit())));
    }

    @Bean
    public CacheStore<RefreshTokenDataCache> cacheStoreForRefreshTokenData() {
        return new CacheStore<>(
                Long.parseLong(ACCESS_TOKEN_EXPIRATION_TIME),
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
    
    @Bean
    public Set<String> allowedClientsOrigins() {
        return Collections.synchronizedSet(new HashSet<>());
    }

}
