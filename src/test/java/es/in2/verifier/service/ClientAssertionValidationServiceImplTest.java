package es.in2.verifier.service;

import com.nimbusds.jose.Payload;
import es.in2.verifier.infrastructure.config.ApplicationConfig;
import es.in2.verifier.infrastructure.repository.JtiTokenCache;
import es.in2.verifier.domain.service.JWTService;
import es.in2.verifier.domain.service.impl.ClientAssertionValidationServiceImpl;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ClientAssertionValidationServiceImplTest {

    @Mock
    private JtiTokenCache jtiTokenCache;

    @Mock
    private JWTService jwtService;

    @Mock
    private ApplicationConfig applicationConfig;

    @InjectMocks
    private ClientAssertionValidationServiceImpl clientAssertionValidationService;

    @Test
    void validateClientAssertion_shouldReturnTrue() {
        String clientId = "1234";
        String authServer = "authorization-server";
        String jti = "jti";
        Payload payloadMock = mock(Payload.class);

        when(applicationConfig.getAuthorizationServerUrl()).thenReturn(authServer);
        when(jwtService.getClaimFromPayload(payloadMock,"iss")).thenReturn(clientId);
        when(jwtService.getClaimFromPayload(payloadMock,"sub")).thenReturn(clientId);
        when(jwtService.getClaimFromPayload(payloadMock,"aud")).thenReturn("authorization-server");
        when(jwtService.getClaimFromPayload(payloadMock,"jti")).thenReturn(jti);
        when(jtiTokenCache.isJtiPresent(jti)).thenReturn(false);
        when(jwtService.getExpirationFromPayload(payloadMock)).thenReturn(System.currentTimeMillis() / 1000 + 3600);

        boolean result = clientAssertionValidationService.validateClientAssertionJWTClaims(clientId, payloadMock);

        assertTrue(result);

    }

    @Test
    void validateClientAssertionJWTClaims_invalidIssuer_shouldReturnFalse() {
        String clientId = "1234";
        Payload mockPayload = mock(Payload.class);

        when(jwtService.getClaimFromPayload(mockPayload, "iss")).thenReturn("invalidClient");

        boolean result = clientAssertionValidationService.validateClientAssertionJWTClaims(clientId, mockPayload);

        assertFalse(result);
    }

    @Test
    void validateClientAssertionJWTClaims_invalidSubject_shouldReturnFalse() {
        String clientId = "1234";
        Payload mockPayload = mock(Payload.class);

        when(jwtService.getClaimFromPayload(mockPayload, "iss")).thenReturn(clientId);
        when(jwtService.getClaimFromPayload(mockPayload, "sub")).thenReturn("invalidSubject");

        boolean result = clientAssertionValidationService.validateClientAssertionJWTClaims(clientId, mockPayload);

        assertFalse(result);
    }

    @Test
    void validateClientAssertionJWTClaims_invalidAudience_shouldReturnFalse() {
        String clientId = "1234";
        Payload mockPayload = mock(Payload.class);

        when(jwtService.getClaimFromPayload(mockPayload, "iss")).thenReturn(clientId);
        when(jwtService.getClaimFromPayload(mockPayload, "sub")).thenReturn(clientId);
        when(jwtService.getClaimFromPayload(mockPayload, "aud")).thenReturn("wrongAudience");
        when(applicationConfig.getAuthorizationServerUrl()).thenReturn("expectedAudience");

        boolean result = clientAssertionValidationService.validateClientAssertionJWTClaims(clientId, mockPayload);

        assertFalse(result);
    }

    @Test
    void validateClientAssertionJWTClaims_jtiAlreadyUsed_shouldReturnFalse() {
        String clientId = "1234";
        Payload mockPayload = mock(Payload.class);

        when(jwtService.getClaimFromPayload(mockPayload, "iss")).thenReturn(clientId);
        when(jwtService.getClaimFromPayload(mockPayload, "sub")).thenReturn(clientId);
        when(jwtService.getClaimFromPayload(mockPayload, "aud")).thenReturn("expectedAudience");
        when(applicationConfig.getAuthorizationServerUrl()).thenReturn("expectedAudience");
        when(jwtService.getClaimFromPayload(mockPayload, "jti")).thenReturn("duplicate-jti");
        when(jtiTokenCache.isJtiPresent("duplicate-jti")).thenReturn(true);

        boolean result = clientAssertionValidationService.validateClientAssertionJWTClaims(clientId, mockPayload);

        assertFalse(result);
    }

    @Test
    void validateClientAssertionJWTClaims_expiredToken_shouldReturnFalse() {
        String clientId = "1234";
        Payload mockPayload = mock(Payload.class);

        when(jwtService.getClaimFromPayload(mockPayload, "iss")).thenReturn(clientId);
        when(jwtService.getClaimFromPayload(mockPayload, "sub")).thenReturn(clientId);
        when(jwtService.getClaimFromPayload(mockPayload, "aud")).thenReturn("expectedAudience");
        when(applicationConfig.getAuthorizationServerUrl()).thenReturn("expectedAudience");
        when(jwtService.getExpirationFromPayload(mockPayload)).thenReturn(System.currentTimeMillis() / 1000 - 3600);

        boolean result = clientAssertionValidationService.validateClientAssertionJWTClaims(clientId, mockPayload);

        assertFalse(result);
    }
}
