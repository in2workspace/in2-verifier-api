package es.in2.vcverifier.security.filters;

import com.nimbusds.jose.Payload;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.component.CryptoComponent;
import es.in2.vcverifier.config.CacheStore;
import es.in2.vcverifier.config.properties.SecurityProperties;
import es.in2.vcverifier.exception.UnsupportedScopeException;
import es.in2.vcverifier.service.DIDService;
import es.in2.vcverifier.service.JWTService;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.security.PublicKey;
import java.util.List;
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
    private CacheStore<OAuth2AuthorizationRequest> cacheStoreForOAuth2AuthorizationRequest;

    @Mock
    private SecurityProperties securityProperties;

    @Mock
    private RegisteredClientRepository registeredClientRepository;

    @InjectMocks
    private CustomAuthorizationRequestConverter converter;

    @Test
    void convert_validStandardRequest_shouldReturnAuthentication() {
        // Arrange
        HttpServletRequest request = mock(HttpServletRequest.class);
        String clientId = "test-client-id";
        String state = "test-state";
        String scope = "openid learcredential";
        String redirectUri = "https://client.example.com/callback";
        List<String> authorizationGrantTypes = List.of("code");
        List<String> redirectUris = List.of(redirectUri);

        when(request.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(clientId);
        when(request.getParameter(OAuth2ParameterNames.STATE)).thenReturn(state);
        when(request.getParameter(OAuth2ParameterNames.SCOPE)).thenReturn(scope);
        when(request.getParameter(OAuth2ParameterNames.REDIRECT_URI)).thenReturn(redirectUri);
        when(request.getParameter(REQUEST_URI)).thenReturn(null);
        when(request.getParameter("request")).thenReturn(null);

        RegisteredClient registeredClient = RegisteredClient.withId("1234")
                .clientId("1234")
                .clientName("https://client.example.com")
                .authorizationGrantTypes(grantTypes -> authorizationGrantTypes.forEach(grantType -> grantTypes.add(new AuthorizationGrantType(grantType))))
                .redirectUris(uris -> uris.addAll(redirectUris))
                .build();

        when(registeredClientRepository.findByClientId(clientId)).thenReturn(registeredClient);

        when(securityProperties.authorizationServer()).thenReturn("https://auth.server.com");

        // Mock JWT generation
        ECKey ecKey = mock(ECKey.class);
        when(cryptoComponent.getECKey()).thenReturn(ecKey);
        when(ecKey.getKeyID()).thenReturn("key-id");
        when(jwtService.generateJWT(anyString())).thenReturn("signed-auth-request");

        // Act & Assert
        OAuth2AuthorizationCodeRequestAuthenticationException exception = assertThrows(
                OAuth2AuthorizationCodeRequestAuthenticationException.class,
                () -> converter.convert(request)
        );

        OAuth2Error error = exception.getError();
        assertEquals("custom_error", error.getErrorCode());

        String redirectUrl = error.getUri();
        assertTrue(redirectUrl.contains("authRequest="));
        assertTrue(redirectUrl.contains("state="));
        assertTrue(redirectUrl.contains("homeUri="));
    }

    @Test
    void convert_standardRequest_missingRedirectUri_shouldThrowException() {
        // Arrange
        HttpServletRequest request = mock(HttpServletRequest.class);
        String clientId = "test-client-id";
        String state = "test-state";
        String scope = "openid learcredential";
        String redirectUri = "https://client.example.com/callback";

        when(request.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(clientId);
        when(request.getParameter(OAuth2ParameterNames.STATE)).thenReturn(state);
        when(request.getParameter(OAuth2ParameterNames.SCOPE)).thenReturn(scope);
        when(request.getParameter(OAuth2ParameterNames.REDIRECT_URI)).thenReturn(redirectUri);
        when(request.getParameter(REQUEST_URI)).thenReturn(null);
        when(request.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(clientId);

        // Act & Assert
        OAuth2AuthenticationException exception = assertThrows(
                OAuth2AuthenticationException.class,
                () -> converter.convert(request)
        );

        assertEquals(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT, exception.getError().getErrorCode());
    }

    @Test
    void convert_standardRequest_unsupportedScope_shouldThrowException() {
        // Arrange
        HttpServletRequest request = mock(HttpServletRequest.class);
        String clientId = "test-client-id";
        String state = "test-state";
        String scope = "unsupported_scope";
        String redirectUri = "https://client.example.com/callback";
        RegisteredClient registeredClient = mock(RegisteredClient.class);

        when(request.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(clientId);
        when(request.getParameter(OAuth2ParameterNames.STATE)).thenReturn(state);
        when(request.getParameter(OAuth2ParameterNames.SCOPE)).thenReturn(scope);
        when(request.getParameter(OAuth2ParameterNames.REDIRECT_URI)).thenReturn(redirectUri);
        when(request.getParameter(REQUEST_URI)).thenReturn(null);
        when(request.getParameter("request")).thenReturn(null);

        when(registeredClientRepository.findByClientId(clientId)).thenReturn(registeredClient);
        when(registeredClient.getRedirectUris()).thenReturn(Set.of(redirectUri));

        when(securityProperties.authorizationServer()).thenReturn("https://auth.server.com");

        // Act & Assert
        UnsupportedScopeException exception = assertThrows(
                UnsupportedScopeException.class,
                () -> converter.convert(request)
        );

        assertEquals("Unsupported scope: " + scope, exception.getMessage());
    }

    @Test
    void convert_validFAPIRequestWithRequestParameter_shouldProcessSuccessfully(){
        // Arrange
        HttpServletRequest request = mock(HttpServletRequest.class);
        String clientId = "test-client-id";
        String state = "test-state";
        String scope = "openid learcredential";
        String redirectUri = "https://client.example.com/callback";
        String jwt = "mock-jwt-token"; // Este es el JWT pasado en el parámetro 'request'

        RegisteredClient registeredClient = mock(RegisteredClient.class);

        when(request.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(clientId);
        when(request.getParameter(OAuth2ParameterNames.STATE)).thenReturn(state);
        when(request.getParameter(OAuth2ParameterNames.SCOPE)).thenReturn(scope);
        when(request.getParameter(OAuth2ParameterNames.REDIRECT_URI)).thenReturn(redirectUri);
        when(request.getParameter(REQUEST_URI)).thenReturn(null);
        when(request.getParameter("request")).thenReturn(jwt);

        when(registeredClientRepository.findByClientId(clientId)).thenReturn(registeredClient);
        when(registeredClient.getRedirectUris()).thenReturn(Set.of(redirectUri));
        when(registeredClient.getClientName()).thenReturn("Test Client");

        // Mock JWT parsing and validation
        SignedJWT signedJWT = mock(SignedJWT.class);
        Payload payload = mock(Payload.class);
        when(signedJWT.getPayload()).thenReturn(payload);
        when(jwtService.parseJWT(jwt)).thenReturn(signedJWT);
        when(jwtService.getClaimFromPayload(payload, OAuth2ParameterNames.CLIENT_ID)).thenReturn(clientId);
        when(jwtService.getClaimFromPayload(payload, OAuth2ParameterNames.SCOPE)).thenReturn(scope);
        when(jwtService.getClaimFromPayload(payload, OAuth2ParameterNames.REDIRECT_URI)).thenReturn(redirectUri);

        // Mock public key retrieval and JWT verification
        PublicKey publicKey = mock(PublicKey.class);
        when(didService.getPublicKeyFromDid(clientId)).thenReturn(publicKey);
        when(signedJWT.serialize()).thenReturn("serialized-jwt");
        doNothing().when(jwtService).verifyJWTWithECKey(anyString(), eq(publicKey));

        // Mock JWT generation
        ECKey ecKey = mock(ECKey.class);
        when(ecKey.getKeyID()).thenReturn("key-id");
        when(cryptoComponent.getECKey()).thenReturn(ecKey);
        when(jwtService.generateJWT(anyString())).thenReturn("signed-auth-request");

        when(securityProperties.authorizationServer()).thenReturn("https://auth.server.com");

        // Act & Assert
        OAuth2AuthorizationCodeRequestAuthenticationException exception = assertThrows(
                OAuth2AuthorizationCodeRequestAuthenticationException.class,
                () -> converter.convert(request)
        );

        OAuth2Error error = exception.getError();
        assertEquals("custom_error", error.getErrorCode());

        String redirectUrl = error.getUri();
        assertTrue(redirectUrl.contains("authRequest="));
        assertTrue(redirectUrl.contains("state="));
        assertTrue(redirectUrl.contains("homeUri="));

        // Verify that the OAuth2AuthorizationRequest was cached
        verify(cacheStoreForOAuth2AuthorizationRequest).add(eq(state), any(OAuth2AuthorizationRequest.class));
    }


}
