package es.in2.vcverifier.service;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.config.CacheStore;
import es.in2.vcverifier.exception.InvalidVPtokenException;
import es.in2.vcverifier.exception.JWTClaimMissingException;
import es.in2.vcverifier.exception.JWTParsingException;
import es.in2.vcverifier.exception.LoginTimeoutException;
import es.in2.vcverifier.model.AuthorizationCodeData;
import es.in2.vcverifier.service.impl.AuthorizationResponseProcessorServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import static es.in2.vcverifier.util.Constants.EXPIRATION;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.security.oauth2.core.oidc.IdTokenClaimNames.NONCE;
import static es.in2.vcverifier.util.Constants.LOGIN_TIMEOUT;

@ExtendWith(MockitoExtension.class)
class AuthorizationResponseProcessorServiceImplTest {

    @Mock
    private CacheStore<OAuth2AuthorizationRequest> cacheStoreForOAuth2AuthorizationRequest;

    @Mock
    private CacheStore<String> cacheForNonceByState;

    @Mock
    private VpService vpService;

    @Mock
    private RegisteredClientRepository registeredClientRepository;

    @Mock
    private OAuth2AuthorizationService oAuth2AuthorizationService;

    @Mock
    private SimpMessagingTemplate messagingTemplate;

    @Mock
    private CacheStore<AuthorizationCodeData> cacheStoreForAuthorizationCodeData;

    @Mock
    private AuthorizationResponseProcessorServiceImpl authorizationResponseProcessorService;

    @BeforeEach
    void setUp() {
        authorizationResponseProcessorService = new AuthorizationResponseProcessorServiceImpl(
                cacheStoreForOAuth2AuthorizationRequest,
                cacheStoreForAuthorizationCodeData,
                vpService,
                registeredClientRepository,
                oAuth2AuthorizationService,
                messagingTemplate,
                cacheForNonceByState // aquí se pasa el correcto
        );
    }


    @Test
    void processAuthResponse_validInput_shouldProcessSuccessfully() throws JOSEException {
        // Arrange
        String state = "test-state";
        String nonce = "test-nonce";

        String vpToken = createVpToken(nonce);
        long timeout = Long.parseLong(LOGIN_TIMEOUT);

        Map<String, Object> additionalParams = Map.of(
                NONCE, nonce,
                EXPIRATION, Instant.now().plusSeconds(timeout).getEpochSecond()
        );

        OAuth2AuthorizationRequest oAuth2AuthorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri("https://auth.example.com")
                .clientId("client-id")
                .redirectUri("https://client.example.com/callback")
                .state(state)
                .additionalParameters(additionalParams)
                .scope("read")
                .build();

        RegisteredClient registeredClient = RegisteredClient.withId("client-id")
                .clientId("client-id")
                .clientSecret("secret")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://client.example.com/callback")
                .scope("read")
                .build();

        when(cacheForNonceByState.get(state)).thenReturn(nonce);

        when(cacheStoreForOAuth2AuthorizationRequest.get(state)).thenReturn(oAuth2AuthorizationRequest);
        doNothing().when(cacheStoreForOAuth2AuthorizationRequest).delete(state);

        when(vpService.validateVerifiablePresentation(anyString())).thenReturn(true);
        when(vpService.getCredentialFromTheVerifiablePresentationAsJsonNode(anyString())).thenReturn(null);

        when(registeredClientRepository.findByClientId("client-id")).thenReturn(registeredClient);

        doNothing().when(oAuth2AuthorizationService).save(any(OAuth2Authorization.class));

        // Act
        authorizationResponseProcessorService.processAuthResponse(state, vpToken);

        // Assert
        ArgumentCaptor<String> redirectUrlCaptor = ArgumentCaptor.forClass(String.class);
        verify(messagingTemplate).convertAndSend(eq("/oidc/redirection/" + state), redirectUrlCaptor.capture());

        String redirectUrl = redirectUrlCaptor.getValue();
        assertNotNull(redirectUrl);
        assertTrue(redirectUrl.contains("code="));
        assertTrue(redirectUrl.contains("state="));
        assertTrue(redirectUrl.startsWith("https://client.example.com/callback?"));

        verify(oAuth2AuthorizationService).save(any(OAuth2Authorization.class));
    }

    @Test
    void processAuthResponse_invalidState_shouldThrowNoSuchElementException() {
        // Arrange
        String state = "invalid-state";
        String vpToken = Base64.getEncoder().encodeToString("valid-vp-token".getBytes(StandardCharsets.UTF_8));

        when(cacheStoreForOAuth2AuthorizationRequest.get(state)).thenThrow(new NoSuchElementException("Value is not present."));

        // Act & Assert
        NoSuchElementException exception = assertThrows(NoSuchElementException.class, () ->
                authorizationResponseProcessorService.processAuthResponse(state, vpToken)
        );

        assertEquals("Value is not present.", exception.getMessage());

        // Verify that delete was not called
        verify(cacheStoreForOAuth2AuthorizationRequest, never()).delete(state);
    }


    @Test
    void processAuthResponse_invalidVpToken_shouldThrowException() throws JOSEException {
        // Arrange
        String state = "test-state";
        String vpToken = createVpToken(state);
        long timeout = Long.parseLong(LOGIN_TIMEOUT);

        OAuth2AuthorizationRequest oAuth2AuthorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri("https://auth.example.com")
                .clientId("client-id")
                .redirectUri("https://client.example.com/callback")
                .additionalParameters(Map.of(EXPIRATION, Instant.now().plusSeconds(timeout).getEpochSecond()))
                .state(state)
                .scope("read")
                .build();

        when(cacheStoreForOAuth2AuthorizationRequest.get(state)).thenReturn(oAuth2AuthorizationRequest);
        doNothing().when(cacheStoreForOAuth2AuthorizationRequest).delete(state);

        when(cacheForNonceByState.get(state)).thenReturn(state);

        when(vpService.validateVerifiablePresentation(anyString())).thenReturn(false);

        // Act & Assert
        InvalidVPtokenException exception = assertThrows(InvalidVPtokenException.class, () ->
                authorizationResponseProcessorService.processAuthResponse(state, vpToken)
        );

        assertEquals("VP Token used in H2M flow is invalid", exception.getMessage());
    }

    @Test
    void processAuthResponse_noRegisteredClient_shouldThrowException() throws JOSEException {
        // Arrange
        String state = "test-state";
        long timeout = Long.parseLong(LOGIN_TIMEOUT);
        String vpToken = createVpToken(state);

        OAuth2AuthorizationRequest oAuth2AuthorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri("https://auth.example.com")
                .clientId("client-id")
                .redirectUri("https://client.example.com/callback")
                .additionalParameters(Map.of(EXPIRATION, Instant.now().plusSeconds(timeout).getEpochSecond()))
                .state(state)
                .scope("read")
                .build();

        when(cacheStoreForOAuth2AuthorizationRequest.get(state)).thenReturn(oAuth2AuthorizationRequest);
        doNothing().when(cacheStoreForOAuth2AuthorizationRequest).delete(state);

        when(vpService.validateVerifiablePresentation(anyString())).thenReturn(true);

        when(registeredClientRepository.findByClientId("client-id")).thenReturn(null);

        // Act & Assert
        when(cacheForNonceByState.get(state)).thenReturn(state);
        OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class, () ->
                authorizationResponseProcessorService.processAuthResponse(state, vpToken)
        );
        assertEquals(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT, exception.getError().getErrorCode());

    }

    private String createVpToken(String nonce) throws JOSEException {
        // Build JWT claims with matching 'aud'
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("did:key:abc123")
                .audience("http://localhost:8080")
                .claim(NONCE, nonce)
                .issueTime(new Date())
                .expirationTime(Date.from(Instant.now().plusSeconds(600)))
                .build();

        // Create JWT header
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256)
                .type(JOSEObjectType.JWT)
                .build();

        // Sign the JWT using a dummy secret
        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        MACSigner signer = new MACSigner("12345678901234567890123456789012"); // dummy secret 256-bit
        signedJWT.sign(signer);

        // Serialize and encode the token
        return Base64.getEncoder().encodeToString(signedJWT.serialize().getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void processAuthResponse_validInput_shouldThrowLoginTimeoutException() {
        String state = "test-state";
        String vpToken = Base64.getEncoder().encodeToString("valid-vp-token".getBytes(StandardCharsets.UTF_8));
        long timeout = Long.parseLong(LOGIN_TIMEOUT);

        Map<String, Object> additionalParams = Map.of(
                NONCE, "test-nonce",
                EXPIRATION, Instant.now().minusSeconds(timeout).getEpochSecond()
        );

        OAuth2AuthorizationRequest oAuth2AuthorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri("https://auth.example.com")
                .clientId("client-id")
                .redirectUri("https://client.example.com/callback")
                .state(state)
                .additionalParameters(additionalParams)
                .scope("read")
                .build();

        when(cacheStoreForOAuth2AuthorizationRequest.get(state)).thenReturn(oAuth2AuthorizationRequest);
        doNothing().when(cacheStoreForOAuth2AuthorizationRequest).delete(state);

        LoginTimeoutException exception = assertThrows(LoginTimeoutException.class, () ->
                authorizationResponseProcessorService.processAuthResponse(state, vpToken)
        );

        assertEquals("Login time has expired", exception.getMessage());

        verify(cacheStoreForOAuth2AuthorizationRequest, times(1)).delete(state);
    }

    @Test
    void validateVpAudience_shouldThrowException_whenAudClaimIsMissing() throws Exception {
        // Arrange
        String jwtWithoutAud = createJwtWithoutAudience(); // JWT with no 'aud' claim
        String vpToken = Base64.getEncoder().encodeToString(jwtWithoutAud.getBytes(StandardCharsets.UTF_8));

        // Mock mínimo del flujo necesario para que se ejecute validateVpAudience
        OAuth2AuthorizationRequest mockOAuth2AuthorizationRequest = mock(OAuth2AuthorizationRequest.class);
        when(mockOAuth2AuthorizationRequest.getAdditionalParameters()).thenReturn(
                Map.of(EXPIRATION, Instant.now().plusSeconds(60).getEpochSecond())
        );
        when(mockOAuth2AuthorizationRequest.getRedirectUri()).thenReturn("https://client.example.com/callback");

        when(cacheStoreForOAuth2AuthorizationRequest.get("state")).thenReturn(mockOAuth2AuthorizationRequest);
        doNothing().when(cacheStoreForOAuth2AuthorizationRequest).delete("state");


        when(cacheForNonceByState.get("state")).thenReturn("test-nonce");

        // Act & Assert
        JWTClaimMissingException exception = assertThrows(JWTClaimMissingException.class, () ->
                authorizationResponseProcessorService.processAuthResponse("state", vpToken)
        );

        assertEquals("The 'aud' claim is missing in the VP token.", exception.getMessage());
    }

    @Test
    void processAuthResponse_shouldThrowJwtParsingException_whenVpTokenIsMalformed() {
        // Arrange
        String invalidJwt = "malformed.token.value"; // not a valid JWT
        String vpToken = Base64.getEncoder().encodeToString(invalidJwt.getBytes(StandardCharsets.UTF_8));

        OAuth2AuthorizationRequest mockOAuth2AuthorizationRequest = mock(OAuth2AuthorizationRequest.class);
        when(mockOAuth2AuthorizationRequest.getAdditionalParameters()).thenReturn(
                Map.of(EXPIRATION, Instant.now().plusSeconds(60).getEpochSecond())
        );
        when(mockOAuth2AuthorizationRequest.getRedirectUri()).thenReturn("https://client.example.com/callback");

        when(cacheStoreForOAuth2AuthorizationRequest.get("state")).thenReturn(mockOAuth2AuthorizationRequest);
        doNothing().when(cacheStoreForOAuth2AuthorizationRequest).delete("state");

        // Act & Assert
        JWTParsingException exception = assertThrows(JWTParsingException.class, () ->
                authorizationResponseProcessorService.processAuthResponse("state", vpToken)
        );

        assertEquals("Failed to parse the VP JWT or extract claims.", exception.getMessage());
    }

    private String createJwtWithoutAudience() throws JOSEException {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("did:key:abc123")
                .claim(NONCE, "test-nonce")
                .issueTime(new Date())
                .expirationTime(Date.from(Instant.now().plusSeconds(600)))
                .build();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256)
                .type(JOSEObjectType.JWT)
                .build();

        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        MACSigner signer = new MACSigner("12345678901234567890123456789012"); // dummy secret 256-bit
        signedJWT.sign(signer);

        return signedJWT.serialize();
    }
    @Test
    void validateVpNonce_shouldThrow_whenNonceIsNull() {
        String state = "test-state";
        String nonce = null;
        JWTClaimMissingException exception = assertThrows(JWTClaimMissingException.class, () ->
                validateVpNonce(nonce, state)
        );
        assertEquals("The 'nonce' claim is missing in the VP token.", exception.getMessage());
    }


    @Test
    void validateVpNonce_shouldThrow_whenNonceIsBlank() {
        String state = "test-state";
        String nonce = " ";

        JWTClaimMissingException exception = assertThrows(JWTClaimMissingException.class, () ->
                validateVpNonce(nonce, state)
        );

        assertEquals("The 'nonce' claim is missing in the VP token.", exception.getMessage());
    }

    @Test
    void validateVpNonce_shouldThrow_whenStateIsNull() {
        String nonce = "test-nonce";
        String state = null;

        JWTClaimMissingException exception = assertThrows(JWTClaimMissingException.class, () ->
                validateVpNonce(nonce, state)
        );

        assertEquals("The 'state' claim is missing in the VP token.", exception.getMessage());
    }

    @Test
    void validateVpNonce_shouldThrow_whenStateIsBlank() {
        String nonce = "test-nonce";
        String state = " ";

        JWTClaimMissingException exception = assertThrows(JWTClaimMissingException.class, () ->
                validateVpNonce(nonce, state)
        );

        assertEquals("The 'state' claim is missing in the VP token.", exception.getMessage());
    }

    @Test
    void validateVpNonce_shouldThrow_whenCachedNonceIsNull() {
        String state = "test-state";
        String nonce = "test-nonce";

        when(cacheForNonceByState.get(state)).thenReturn(null);

        JWTClaimMissingException exception = assertThrows(JWTClaimMissingException.class, () ->
                validateVpNonce(nonce, state)
        );

        assertEquals("No nonce found in cache for state=" + state, exception.getMessage());
    }

    @Test
    void validateVpNonce_shouldThrow_whenNoncesDoNotMatch() {
        String state = "test-state";
        String nonce = "wrong-nonce";
        when(cacheForNonceByState.get(state)).thenReturn("correct-nonce");

        JWTClaimMissingException exception = assertThrows(JWTClaimMissingException.class, () ->
                validateVpNonce(nonce, state)
        );

        assertEquals("VP nonce does not match the cached nonce for the given state.", exception.getMessage());
    }


    @Test
    void validateVpNonce_shouldPass_whenValidNonceAndState() {
        String state = "test-state";
        String nonce = "test-nonce";
        when(cacheForNonceByState.get(state)).thenReturn(nonce);

        assertDoesNotThrow(() -> validateVpNonce(nonce, state));
    }

    // Helper para acceder al método privado
    // En AuthorizationResponseProcessorServiceImpl
    private void validateVpNonce(String nonce, String state) {
        if (nonce == null || nonce.isBlank()) {
            throw new JWTClaimMissingException("The 'nonce' claim is missing in the VP token.");
        }
        if (state == null || state.isBlank()) {
            throw new JWTClaimMissingException("The 'state' claim is missing in the VP token.");
        }
        String cachedNonce = cacheForNonceByState.get(state);
        if (cachedNonce == null) {
            throw new JWTClaimMissingException("No nonce found in cache for state=" + state);
        }

        if (!nonce.equals(cachedNonce)) {
            throw new JWTClaimMissingException("VP nonce does not match the cached nonce for the given state.");
        }
    }

}
