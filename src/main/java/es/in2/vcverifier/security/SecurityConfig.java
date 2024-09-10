package es.in2.vcverifier.security;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import es.in2.vcverifier.config.CacheStore;
import es.in2.vcverifier.crypto.CryptoComponent;
import es.in2.vcverifier.security.filters.CustomAuthenticationProvider;
import es.in2.vcverifier.security.filters.CustomAuthorizationRequestConverter;
import es.in2.vcverifier.security.filters.CustomAuthorizationResponseHandler;
import es.in2.vcverifier.security.filters.CustomErrorResponseHandler;
import es.in2.vcverifier.service.AuthenticationService;
import es.in2.vcverifier.service.DIDService;
import es.in2.vcverifier.service.JWTService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;

@Slf4j
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CryptoComponent cryptoComponent;
    private final DIDService didService;
    private final JWTService jwtService;
    private final AuthenticationService authenticationService;
    private final CacheStore<String> cacheStoreForRedirectUri;
    private final CacheStore<String> cacheStoreForJwt;


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
                                .authorizationRequestConverter(new CustomAuthorizationRequestConverter(didService,jwtService,authenticationService))
                                // Adds an AuthenticationProvider (main processor) used for authenticating the
                                // OAuth2AuthorizationCodeRequestAuthenticationToken or OAuth2AuthorizationConsentAuthenticationToken.
                                .authenticationProvider(new CustomAuthenticationProvider(cryptoComponent,jwtService,cacheStoreForRedirectUri,cacheStoreForJwt,authenticationService))
                                // The URI of the custom consent page to redirect resource owners to if consent is
                                // required during the authorization request flow.
                                .consentPage("/oidc/consent")
                                // The AuthenticationSuccessHandler (post-processor) used for handling an
                                // “authenticated” OAuth2AuthorizationCodeRequestAuthenticationToken and returning
                                // the OAuth2AuthorizationResponse.
                                .authorizationResponseHandler(new CustomAuthorizationResponseHandler())
                                // The AuthenticationFailureHandler (post-processor) used for handling an
                                // OAuth2AuthorizationCodeRequestAuthenticationException and returning the OAuth2Error
                                // response.
                                .errorResponseHandler(new CustomErrorResponseHandler())
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
                        .requestMatchers("/generate-auth").permitAll()
                        .requestMatchers("/oidc/consent").permitAll()
                        .anyRequest().authenticated()

                )
                // Form login handles the redirect to the login page from the
                // authorization server filter chain
                .csrf(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable);
        return http.build();
    }

    // JWK Set Endpoint
//    @Bean
//    public JWKSource<SecurityContext> jwkSource() {
//        try {
//            JWKSet jwkSet = new JWKSet(cryptoComponent.getECKey());
//            return new ImmutableJWKSet<>(jwkSet);
//        } catch (Exception e) {
//            throw new JWKSourceCreationException("Error creating JWK source");
//        }
//    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        JWKSet jwkSet = new JWKSet(cryptoComponent.getECKey());
        return ( jwkSelector, context ) -> jwkSelector.select(jwkSet);
    }
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
        return context -> {
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                context.getJwsHeader().algorithm(SignatureAlgorithm.ES256);
            }
        };
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    // Customiza los endpoint del Authorization Server
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer("https://localhost:9000")
                .authorizationEndpoint("/oidc/authorize")
                .deviceAuthorizationEndpoint("/oidc/device_authorization")
                .deviceVerificationEndpoint("/oidc/device_verification")
                .tokenEndpoint("/oidc/token")
                .tokenIntrospectionEndpoint("/oidc/introspect")
                .tokenRevocationEndpoint("/oidc/revoke")
                .jwkSetEndpoint("/oidc/jwks")
                .oidcLogoutEndpoint("/oidc/logout")
                .oidcUserInfoEndpoint("/oidc/userinfo")
                .oidcClientRegistrationEndpoint("/oidc/register")
                .build();
    }

}
