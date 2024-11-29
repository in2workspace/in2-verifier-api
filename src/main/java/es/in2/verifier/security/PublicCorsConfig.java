package es.in2.verifier.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@RequiredArgsConstructor
public class PublicCorsConfig {

    @Bean
    public CorsConfigurationSource publicCorsConfigurationSource() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();

        // Configure public endpoints
        CorsConfiguration publicConfig = new CorsConfiguration();
        publicConfig.setAllowedOriginPatterns(List.of("*"));
        publicConfig.setAllowedMethods(List.of("GET", "POST"));
        publicConfig.setAllowedHeaders(List.of("Content-Type"));
        publicConfig.setAllowCredentials(false);

        source.registerCorsConfiguration("/health", publicConfig);
        source.registerCorsConfiguration("/oid4vp/auth-request/**", publicConfig);
        source.registerCorsConfiguration("/oid4vp/auth-response", publicConfig);

        return source;
    }
}

