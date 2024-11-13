package es.in2.vcverifier.security.filters;

import com.nimbusds.jose.jwk.ECKey;
import es.in2.vcverifier.component.CryptoComponent;
import es.in2.vcverifier.config.CacheStore;
import es.in2.vcverifier.config.properties.SecurityProperties;
import es.in2.vcverifier.model.AuthorizationRequestJWT;
import es.in2.vcverifier.service.DIDService;
import es.in2.vcverifier.service.JWTService;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.net.http.HttpClient;
import java.util.Set;

import static es.in2.vcverifier.util.Constants.REQUEST_URI;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CustomAuthorizationRequestConverterTest {

    @Mock
    private DIDService didService;

    @Mock
    private JWTService jwtService;

    @Mock
    private CryptoComponent cryptoComponent;

    @Mock
    private CacheStore<AuthorizationRequestJWT> cacheStoreForAuthorizationRequestJWT;

    @Mock
    private CacheStore<OAuth2AuthorizationRequest> cacheStoreForOAuth2AuthorizationRequest;

    @Mock
    private SecurityProperties securityProperties;

    @Mock
    private RegisteredClientRepository registeredClientRepository;

    @Mock
    private HttpClient httpClient;

    @InjectMocks
    private CustomAuthorizationRequestConverter converter;

//    @Test
//    void convert_validStandardRequest_shouldReturnAuthentication() {
//        // Arrange
//        HttpServletRequest request = mock(HttpServletRequest.class);
//        String clientId = "test-client-id";
//        String state = "test-state";
//        String scope = "openid learcredential";
//        String redirectUri = "https://client.example.com/callback";
//        RegisteredClient registeredClient = mock(RegisteredClient.class);
//
//        when(request.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(clientId);
//        when(request.getParameter(OAuth2ParameterNames.STATE)).thenReturn(state);
//        when(request.getParameter(OAuth2ParameterNames.SCOPE)).thenReturn(scope);
//        when(request.getParameter(OAuth2ParameterNames.REDIRECT_URI)).thenReturn(redirectUri);
//        when(request.getParameter(REQUEST_URI)).thenReturn(null);
//        when(request.getParameter("request")).thenReturn(null);
//
//        when(registeredClientRepository.findByClientId(clientId)).thenReturn(registeredClient);
//        when(registeredClient.getRedirectUris()).thenReturn(Set.of(redirectUri));
//        when(registeredClient.getClientName()).thenReturn("Test Client");
//
//        when(securityProperties.authorizationServer()).thenReturn("https://auth.server.com");
//
//        // Mock JWT generation
//        when(cryptoComponent.getECKey()).thenReturn(mock(ECKey.class));
//        when(jwtService.generateJWT(anyString())).thenReturn("signed-auth-request");
//
//        // Act & Assert
//        OAuth2AuthorizationCodeRequestAuthenticationException exception = assertThrows(
//                OAuth2AuthorizationCodeRequestAuthenticationException.class,
//                () -> converter.convert(request)
//        );
//
//        OAuth2Error error = exception.getError();
//        assertEquals("custom_error", error.getErrorCode());
//
//        String redirectUrl = error.getDescription();
//        assertTrue(redirectUrl.contains("/login"));
//        assertTrue(redirectUrl.contains("authRequest="));
//        assertTrue(redirectUrl.contains("state="));
//        assertTrue(redirectUrl.contains("homeUri="));
//
//        // Verify that the OAuth2AuthorizationRequest was cached
//        verify(cacheStoreForOAuth2AuthorizationRequest).add(eq(state), any(OAuth2AuthorizationRequest.class));
//    }


}
