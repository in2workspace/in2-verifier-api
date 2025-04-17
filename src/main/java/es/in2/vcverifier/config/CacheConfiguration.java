package es.in2.vcverifier.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class CacheConfiguration {

    @Bean
    public CacheStore<String> cacheForNonceByState() {
        return new CacheStore<>();
    }
}