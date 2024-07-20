package es.in2.verifier.config;

import es.in2.verifier.repository.CacheStore;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
public class CacheStoreConfig {

    private final ApplicationConfig applicationConfig;

    @Bean
    public CacheStore<String> cacheStore() {
        return new CacheStore<>(applicationConfig.getCacheLifetime(), applicationConfig.getCacheTimeUnit());
    }

}
