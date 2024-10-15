//package es.in2.vcverifier.service;
//
//import com.google.common.cache.Cache;
//import es.in2.vcverifier.config.CacheStore;
//import es.in2.vcverifier.config.properties.SecurityProperties;
//import es.in2.vcverifier.model.AuthorizationCodeData;
//import es.in2.vcverifier.oid4vp.service.impl.AuthorizationResponseProcessorServiceImpl;
//import org.junit.jupiter.api.BeforeEach;
//import org.junit.jupiter.api.Test;
//import org.junit.jupiter.api.extension.ExtendWith;
//import org.mockito.InjectMocks;
//import org.mockito.Mock;
//import org.mockito.junit.jupiter.MockitoExtension;
//import org.springframework.messaging.simp.SimpMessagingTemplate;
//import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
//import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
//import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
//import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
//
//import java.nio.charset.StandardCharsets;
//import java.util.Base64;
//import java.util.NoSuchElementException;
//import java.util.UUID;
//
//import static org.junit.jupiter.api.Assertions.assertEquals;
//import static org.junit.jupiter.api.Assertions.assertThrows;
//import static org.mockito.ArgumentMatchers.anyString;
//import static org.mockito.Mockito.*;
//
//@ExtendWith(MockitoExtension.class)
//public class AuthorizationResponseProcessorServiceImplTest {
//
//    @InjectMocks
//    private AuthorizationResponseProcessorServiceImpl service;
//
//    @Mock
//    private CacheStore<OAuth2AuthorizationRequest> cacheStoreForOAuth2AuthorizationRequest;
//
//    @Mock
//    private CacheStore<AuthorizationCodeData> cacheStoreForAuthorizationCodeData;
//
//    @Mock
//    private VpService vpService;
//
//    @Mock
//    private SecurityProperties securityProperties;
//
//    @Mock
//    private RegisteredClientRepository registeredClientRepository;
//
//    @Mock
//    private OAuth2AuthorizationService oAuth2AuthorizationService;
//
//    @Mock
//    private SimpMessagingTemplate messagingTemplate;
//
//    @Mock
//    private OAuth2AuthorizationRequest oAuth2AuthorizationRequest;
//
//    @Mock
//    private Cache<String, Object> cache;
//
//
//    @BeforeEach
//    void setUp() {
//        when(securityProperties.token()).thenReturn(mock(SecurityProperties.TokenProperties.class));
//        when(securityProperties.token().accessToken()).thenReturn(mock(SecurityProperties.TokenProperties.AccessTokenProperties.class));
//        when(securityProperties.token().accessToken().expiration()).thenReturn("3600");
//        when(securityProperties.token().accessToken().cronUnit()).thenReturn("SECONDS");
//
//    }
//
//    @Test
//    void processAuthResponse_validRequest_shouldProcessSuccessfully() {
//
//        String state = UUID.randomUUID().toString();
//        String vpToken = Base64.getEncoder().encodeToString("valid-vp-token".getBytes(StandardCharsets.UTF_8));
//        OAuth2AuthorizationRequest mockAuthRequest = mock(OAuth2AuthorizationRequest.class);
//        RegisteredClient mockRegisteredClient = mock(RegisteredClient.class);
//
//        when(cache.getIfPresent(state)).thenReturn(mockAuthRequest);
//        when(cacheStoreForOAuth2AuthorizationRequest.get(state)).thenReturn(mockAuthRequest);
//        when(mockAuthRequest.getRedirectUri()).thenReturn("http://localhost:8080/callback");
//
//        when(vpService.validateVerifiablePresentation(anyString())).thenReturn(true);
//
//        when(mockRegisteredClient.getClientId()).thenReturn("client-id");
//        when(registeredClientRepository.findByClientId(anyString())).thenReturn(mockRegisteredClient);
//
//        when(securityProperties.token().accessToken().expiration()).thenReturn("3600");
//        when(securityProperties.token().accessToken().cronUnit()).thenReturn("SECONDS");
//
//        service.processAuthResponse(state, vpToken);
//
//        verify(vpService).validateVerifiablePresentation(anyString());
//        verify(messagingTemplate).convertAndSend(eq("/oidc/redirection/" + state), anyString());
//    }
//
//    @Test
//    void processAuthResponse_InvalidState() {
//        String state = UUID.randomUUID().toString();
//        String vpToken = Base64.getEncoder().encodeToString("valid-vp-token".getBytes());
//
//        when(cacheStoreForOAuth2AuthorizationRequest.get(state)).thenThrow(new NoSuchElementException());
//
//        IllegalStateException exception = assertThrows(IllegalStateException.class, () ->
//                service.processAuthResponse(state, vpToken));
//
//        assertEquals("Invalid or expired state", exception.getMessage());
//    }
//
//    @Test
//    void processAuthResponse_InvalidVpToken() {
//        // Setup
//        String state = UUID.randomUUID().toString();
//        String vpToken = Base64.getEncoder().encodeToString("invalid-vp-token".getBytes());
//        OAuth2AuthorizationRequest mockAuthRequest = mock(OAuth2AuthorizationRequest.class);
//
//        when(cacheStoreForOAuth2AuthorizationRequest.get(state)).thenReturn(mockAuthRequest);
//        when(mockAuthRequest.getRedirectUri()).thenReturn("http://localhost:8080/callback");
//
//        // Simula que el VP token no es válido
//        when(vpService.validateVerifiablePresentation(anyString())).thenReturn(false);
//
//        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () ->
//                service.processAuthResponse(state, vpToken));
//
//        assertEquals("Invalid VP Token", exception.getMessage());
//    }
//}
