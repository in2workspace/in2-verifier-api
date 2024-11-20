package es.in2.vcverifier.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
public class CorsConfig {

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // Allow all origins
        configuration.setAllowedOrigins(List.of("*"));
        // Allow all HTTP methods
        configuration.setAllowedMethods(List.of("GET", "POST"));
        // Allow all headers
        configuration.setAllowedHeaders(List.of("Content-Type"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/health", configuration);
        source.registerCorsConfiguration("/oid4vp/auth-request/**", configuration);
        source.registerCorsConfiguration("/oid4vp/auth-response", configuration);

        return source;
    }

}

