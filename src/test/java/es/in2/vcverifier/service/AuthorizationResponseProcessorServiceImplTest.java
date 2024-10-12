//package es.in2.vcverifier.service;
//
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
//import java.util.UUID;
//
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
//    private String state;
//    private String vpToken;
//
//    @BeforeEach
//    void setUp() {
//        state = UUID.randomUUID().toString();
//        vpToken = Base64.getEncoder().encodeToString("valid-vp-token".getBytes(StandardCharsets.UTF_8));
//
//        when(securityProperties.token()).thenReturn(mock(SecurityProperties.TokenProperties.class));
//        when(securityProperties.token().accessToken()).thenReturn(mock(SecurityProperties.TokenProperties.AccessTokenProperties.class));
//        when(securityProperties.token().accessToken().expiration()).thenReturn("3600");
//        when(securityProperties.token().accessToken().cronUnit()).thenReturn("SECONDS");
//    }
//
//    @Test
//    void processAuthResponse_validRequest_shouldProcessSuccessfully() {
//        // Arrange
//        when(oAuth2AuthorizationRequest.getRedirectUri()).thenReturn("http://redirect.url");
//
//        // Mock the cache to return the mock authorization request when the state is provided
//        when(cacheStoreForOAuth2AuthorizationRequest.get(state)).thenReturn(oAuth2AuthorizationRequest);
//
//        // Mock VP service validation
//        when(vpService.validateVerifiablePresentation(anyString())).thenReturn(true);
//
//        // Mock RegisteredClient
//        RegisteredClient registeredClient = mock(RegisteredClient.class);
//        when(registeredClient.getClientId()).thenReturn("client-id");
//        when(registeredClientRepository.findByClientId(anyString())).thenReturn(registeredClient);
//
//        // Mock security properties
//        when(securityProperties.token().accessToken().expiration()).thenReturn("3600");
//        when(securityProperties.token().accessToken().cronUnit()).thenReturn("SECONDS");
//
//        // Act
//        service.processAuthResponse(state, vpToken);
//
//        // Assert
//        verify(vpService).validateVerifiablePresentation(anyString());
//        verify(messagingTemplate).convertAndSend(eq("/oidc/redirection/" + state), anyString());
//    }
//}
