package es.in2.verifier.security;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

@Slf4j
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CorsConfig corsConfig;

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors(cors -> cors.configurationSource(corsConfig.corsConfigurationSource()))
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/health").permitAll()
                        .requestMatchers("/oid4vp/auth-request/*").permitAll()
                        .requestMatchers("/oid4vp/auth-response").permitAll()
                        .requestMatchers("/login").permitAll()
                        .requestMatchers("/client-error").permitAll()
                        .requestMatchers("/oidc/did/*").permitAll()
                        .requestMatchers("/qr-socket/**").permitAll()
                        .requestMatchers("/img/**").permitAll()
                        .anyRequest().authenticated()
                )
                .csrf(csrf -> csrf
                        // Apply CSRF protection only to the specified routes
                        .requireCsrfProtectionMatcher(new CsrfProtectionMatcher())
                )
                .formLogin(AbstractHttpConfigurer::disable);
        return http.build();
    }


    private static class CsrfProtectionMatcher implements RequestMatcher {
        private final AntPathRequestMatcher[] requestMatchers = {
                new AntPathRequestMatcher("/oid4vp/auth-request/**"),
                new AntPathRequestMatcher("/oid4vp/auth-response"),
        };

        @Override
        public boolean matches(HttpServletRequest request) {
            // Disables CSRF only for the specified routes
            for (AntPathRequestMatcher matcher : requestMatchers) {
                if (matcher.matches(request)) {
                    return false;
                }
            }
            // Applies CSRF protection to all other routes
            return true;
        }
    }

}
