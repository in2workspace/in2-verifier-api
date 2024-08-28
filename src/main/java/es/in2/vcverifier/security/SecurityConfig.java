package es.in2.vcverifier.security;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import es.in2.vcverifier.crypto.CryptoComponent;
import es.in2.vcverifier.security.filters.CustomAuthenticationProvider;
import es.in2.vcverifier.security.filters.CustomAuthorizationRequestConverter;
import es.in2.vcverifier.security.filters.CustomAuthorizationResponseHandler;
import es.in2.vcverifier.security.filters.CustomErrorResponseHandler;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;

@Slf4j
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CryptoComponent cryptoComponent;


    // A Spring Security filter chain for the Protocol Endpoints.
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        http
                .getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .authorizationEndpoint(authorizationEndpoint ->
                        authorizationEndpoint
                                // Adds an AuthenticationConverter (pre-processor) used when attempting to extract
                                // an OAuth2 authorization request (or consent) from HttpServletRequest to an instance
                                // of OAuth2AuthorizationCodeRequestAuthenticationToken or OAuth2AuthorizationConsentAuthenticationToken.
                                .authorizationRequestConverter(new CustomAuthorizationRequestConverter())
                                // Adds an AuthenticationProvider (main processor) used for authenticating the
                                // OAuth2AuthorizationCodeRequestAuthenticationToken or OAuth2AuthorizationConsentAuthenticationToken.
                                .authenticationProvider(new CustomAuthenticationProvider())
                                // The AuthenticationSuccessHandler (post-processor) used for handling an
                                // “authenticated” OAuth2AuthorizationCodeRequestAuthenticationToken and returning
                                // the OAuth2AuthorizationResponse.
                                .authorizationResponseHandler(new CustomAuthorizationResponseHandler())
                                // The AuthenticationFailureHandler (post-processor) used for handling an
                                // OAuth2AuthorizationCodeRequestAuthenticationException and returning the OAuth2Error
                                // response.
                                .errorResponseHandler(new CustomErrorResponseHandler())
                                // The URI of the custom consent page to redirect resource owners to if consent is
                                // required during the authorization request flow.
                                .consentPage("/oauth2/v1/h2m/authorize")
                )
                .oidc(Customizer.withDefaults());    // Enable OpenID Connect 1.0

        http
                .csrf(AbstractHttpConfigurer::disable) // We use JWT tokens instead of sessions
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .oauth2ResourceServer(resourceServer -> resourceServer
                        .jwt(Customizer.withDefaults()));

        return http.build();
    }

    // A Spring Security filter chain for authentication.
    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
            throws Exception {

        http
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().authenticated()
                )
                // Form login handles the redirect to the login page from the
                // authorization server filter chain
                .formLogin(Customizer.withDefaults());

        return http.build();
    }

    // JWK Set Endpoint
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        try {
            JWKSet jwkSet = new JWKSet(cryptoComponent.getECKey());
            return new ImmutableJWKSet<>(jwkSet);
        } catch (Exception e) {
            throw new JWKSourceCreationException("Error creating JWK source");
        }
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

}
