package es.in2.vcverifier.service;

import es.in2.vcverifier.config.CacheStore;
import es.in2.vcverifier.exception.InvalidVPtokenException;
import es.in2.vcverifier.service.impl.AuthorizationResponseProcessorServiceImpl;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
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

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.NoSuchElementException;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.security.oauth2.core.oidc.IdTokenClaimNames.NONCE;

@ExtendWith(MockitoExtension.class)
class AuthorizationResponseProcessorServiceImplTest {

    @Mock
    private CacheStore<OAuth2AuthorizationRequest> cacheStoreForOAuth2AuthorizationRequest;


    @Mock
    private VpService vpService;

    @Mock
    private RegisteredClientRepository registeredClientRepository;

    @Mock
    private OAuth2AuthorizationService oAuth2AuthorizationService;

    @Mock
    private SimpMessagingTemplate messagingTemplate;

    @InjectMocks
    private AuthorizationResponseProcessorServiceImpl authorizationResponseProcessorService;

    @Test
    void processAuthResponse_validInput_shouldProcessSuccessfully() {
        // Arrange
        String state = "test-state";
        String vpToken = Base64.getEncoder().encodeToString("valid-vp-token".getBytes(StandardCharsets.UTF_8));

        OAuth2AuthorizationRequest oAuth2AuthorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri("https://auth.example.com")
                .clientId("client-id")
                .redirectUri("https://client.example.com/callback")
                .state(state)
                .additionalParameters(Map.of(NONCE, "test-nonce"))
                .scope("read")
                .build();

        RegisteredClient registeredClient = RegisteredClient.withId("client-id")
                .clientId("client-id")
                .clientSecret("secret")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://client.example.com/callback")
                .scope("read")
                .build();

//        SecurityProperties.TokenProperties.AccessTokenProperties accessTokenProperties = mock(SecurityProperties.TokenProperties.AccessTokenProperties.class);
//        SecurityProperties.TokenProperties tokenProperties = mock(SecurityProperties.TokenProperties.class);

        when(cacheStoreForOAuth2AuthorizationRequest.get(state)).thenReturn(oAuth2AuthorizationRequest);
        doNothing().when(cacheStoreForOAuth2AuthorizationRequest).delete(state);

        when(vpService.validateVerifiablePresentation("valid-vp-token")).thenReturn(true);
        when(vpService.getCredentialFromTheVerifiablePresentationAsJsonNode("valid-vp-token")).thenReturn(null); // Mock as needed

        when(registeredClientRepository.findByClientId("client-id")).thenReturn(registeredClient);

//        when(securityProperties.token()).thenReturn(tokenProperties);
//        when(tokenProperties.accessToken()).thenReturn(accessTokenProperties);
//        when(accessTokenProperties.expiration()).thenReturn("5");
//        when(accessTokenProperties.cronUnit()).thenReturn("MINUTES");

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

        // Verify that the authorization was saved
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
    void processAuthResponse_invalidVpToken_shouldThrowException() {
        // Arrange
        String state = "test-state";
        String vpToken = Base64.getEncoder().encodeToString("invalid-vp-token".getBytes(StandardCharsets.UTF_8));

        OAuth2AuthorizationRequest oAuth2AuthorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri("https://auth.example.com")
                .clientId("client-id")
                .redirectUri("https://client.example.com/callback")
                .state(state)
                .scope("read")
                .build();

        when(cacheStoreForOAuth2AuthorizationRequest.get(state)).thenReturn(oAuth2AuthorizationRequest);
        doNothing().when(cacheStoreForOAuth2AuthorizationRequest).delete(state);

        when(vpService.validateVerifiablePresentation("invalid-vp-token")).thenReturn(false);

        // Act & Assert
        InvalidVPtokenException exception = assertThrows(InvalidVPtokenException.class, () ->
                authorizationResponseProcessorService.processAuthResponse(state, vpToken)
        );

        assertEquals("VP Token used in H2M flow is invalid", exception.getMessage());
    }

    @Test
    void processAuthResponse_noRegisteredClient_shouldThrowException() {
        // Arrange
        String state = "test-state";
        String vpToken = Base64.getEncoder().encodeToString("valid-vp-token".getBytes(StandardCharsets.UTF_8));

        OAuth2AuthorizationRequest oAuth2AuthorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri("https://auth.example.com")
                .clientId("client-id")
                .redirectUri("https://client.example.com/callback")
                .state(state)
                .scope("read")
                .build();

        when(cacheStoreForOAuth2AuthorizationRequest.get(state)).thenReturn(oAuth2AuthorizationRequest);
        doNothing().when(cacheStoreForOAuth2AuthorizationRequest).delete(state);

        when(vpService.validateVerifiablePresentation("valid-vp-token")).thenReturn(true);

        when(registeredClientRepository.findByClientId("client-id")).thenReturn(null);

        // Act & Assert
        OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class, () ->
                authorizationResponseProcessorService.processAuthResponse(state, vpToken)
        );

        assertEquals(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT, exception.getError().getErrorCode());
    }
}
