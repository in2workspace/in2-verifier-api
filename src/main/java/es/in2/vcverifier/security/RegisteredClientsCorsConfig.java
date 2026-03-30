package es.in2.vcverifier.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

@Configuration
@RequiredArgsConstructor
public class RegisteredClientsCorsConfig {

    private final Set<String> allowedClientsOrigins;

    @Bean
    public CorsConfigurationSource registeredClientsCorsConfigurationSource() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();

        // Configure endpoints for clients that used the OIDC protocol
        CorsConfiguration authConfig = new CorsConfiguration();
        authConfig.setAllowedOriginPatterns(List.of("*"));
        authConfig.setAllowedMethods(List.of("GET", "POST", "OPTIONS"));
        authConfig.setAllowedHeaders(List.of("*"));
        authConfig.setAllowCredentials(false);

        System.out.println("RegisteredClientsCorsConfig bean loaded");
        System.out.println("allowedClientsOrigins at startup = " + allowedClientsOrigins);
        System.out.println("CORS using allowedOriginPatterns(*) for OIDC endpoints");

        // Register the configuration for each endpoint
        source.registerCorsConfiguration("/oidc/authorize", authConfig);
        source.registerCorsConfiguration("/oidc/device_authorization", authConfig);
        source.registerCorsConfiguration("/oidc/device_verification", authConfig);
        source.registerCorsConfiguration("/oidc/token", authConfig);
        source.registerCorsConfiguration("/oidc/introspect", authConfig);
        source.registerCorsConfiguration("/oidc/revoke", authConfig);
        source.registerCorsConfiguration("/oidc/jwks", authConfig);
        source.registerCorsConfiguration("/oidc/logout", authConfig);
        source.registerCorsConfiguration("/oidc/userinfo", authConfig);
        source.registerCorsConfiguration("/oidc/register", authConfig);
        source.registerCorsConfiguration("/.well-known/openid-configuration", authConfig);

        return source;
    }
}