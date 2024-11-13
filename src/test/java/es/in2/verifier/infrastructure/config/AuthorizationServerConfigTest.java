package es.in2.verifier.infrastructure.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import es.in2.verifier.domain.model.dto.AuthorizationCodeData;
import es.in2.verifier.domain.model.dto.AuthorizationRequestJWT;
import es.in2.verifier.domain.service.ClientAssertionValidationService;
import es.in2.verifier.domain.service.DIDService;
import es.in2.verifier.domain.service.JWTService;
import es.in2.verifier.domain.service.VpService;
import es.in2.verifier.infrastructure.repository.CacheStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthorizationServerConfigTest {

    @Mock
    private CryptoConfig cryptoConfig;

    @Mock
    private DIDService didService;

    @Mock
    private JWTService jwtService;

    @Mock
    private ClientAssertionValidationService clientAssertionValidationService;

    @Mock
    private VpService vpService;

    @Mock
    private CacheStore<AuthorizationRequestJWT> cacheStoreForAuthorizationRequestJWT;

    @Mock
    private CacheStore<OAuth2AuthorizationRequest> cacheStoreForOAuth2AuthorizationRequest;

    @Mock
    private RegisteredClientRepository registeredClientRepository;

    @Mock
    private CacheStore<AuthorizationCodeData> cacheStoreForAuthorizationCodeData;

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private ApplicationConfig applicationConfig;

    @InjectMocks
    private AuthorizationServerConfig authorizationServerConfig;

    @Test
    void jwkSourceReturnsJWKSource() {
        when(cryptoConfig.getECKey()).thenReturn(mock(ECKey.class));
        JWKSource<SecurityContext> result = authorizationServerConfig.jwkSource();
        assertNotNull(result);
    }

    @Test
    void jwtDecoderReturnsJwtDecoder() {
        JWKSource<SecurityContext> jwkSource = mock(JWKSource.class);
        when(applicationConfig.getAuthorizationServerUrl()).thenReturn("http://auth.server");
        JwtDecoder result = authorizationServerConfig.jwtDecoder(jwkSource);
        assertNotNull(result);
    }

    @Test
    void oAuth2AuthorizationServiceReturnsInMemoryOAuth2AuthorizationService() {
        OAuth2AuthorizationService result = authorizationServerConfig.oAuth2AuthorizationService();
        assertTrue(result instanceof InMemoryOAuth2AuthorizationService);
    }

    @Test
    void authorizationServerSettingsReturnsSettings() {
        when(applicationConfig.getAuthorizationServerUrl()).thenReturn("http://auth.server");
        AuthorizationServerSettings result = authorizationServerConfig.authorizationServerSettings();
        assertNotNull(result);
        assertEquals("http://auth.server", result.getIssuer());
    }

}
