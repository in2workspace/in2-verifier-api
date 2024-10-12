package es.in2.vcverifier.security.filters;

import es.in2.vcverifier.config.CacheStore;
import es.in2.vcverifier.crypto.CryptoComponent;
import es.in2.vcverifier.model.AuthorizationRequestJWT;
import es.in2.vcverifier.service.DIDService;
import es.in2.vcverifier.service.JWTService;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.PublicKey;
import java.util.UUID;

import static es.in2.vcverifier.util.Constants.REQUEST_URI;
import static org.junit.jupiter.api.Assertions.assertThrows;
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
    private HttpResponse<String> httpResponse;
    @Mock
    private HttpClient httpClient;

    @Mock
    private HttpServletRequest httpServletRequest;

    @InjectMocks
    private CustomAuthorizationRequestConverter customAuthorizationRequestConverter;

    @Test
    void convert_With_null_requestUri__ShouldThrowUnsupportedScopeException() {
        String clientId = "valid-client-id";
        String state = "valid-state";
        String unsupportedScope = "invalid-scope";

        when(httpServletRequest.getParameter("client_id")).thenReturn(clientId);
        when(httpServletRequest.getParameter("request_uri")).thenReturn(null);
        when(httpServletRequest.getParameter("scope")).thenReturn(unsupportedScope);
        when(httpServletRequest.getParameter("state")).thenReturn(state);

        assertThrows(IllegalArgumentException.class, () -> customAuthorizationRequestConverter.convert(httpServletRequest));
    }

    @Test
    void convert_WithoutClientId_ShouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> customAuthorizationRequestConverter.convert(httpServletRequest));
    }

//    @Test
//    void convert_WhenRequestUriIsProvided_ShouldRetrieveAndVerifyJwt() throws Exception {
//        // Setup
//        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
//        when(mockRequest.getParameter(REQUEST_URI)).thenReturn("https://example.com/jwt/1234");
//        when(mockRequest.getParameter(OAuth2ParameterNames.RESPONSE_TYPE)).thenReturn("code");
//        when(mockRequest.getParameter(OAuth2ParameterNames.SCOPE)).thenReturn("openid learcredential");
//        when(mockRequest.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn("did:key:zDnaeUcW7pAV2xfcEMRsi3tsgYSYkLEf8mbSCZ7YFhKDu6XcR");
//        when(mockRequest.getParameter(OAuth2ParameterNames.STATE)).thenReturn("state");
//
//        String jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWVVY1c3cEFWMnhmY0VNUnNpM3RzZ1lTWWtMRWY4bWJTQ1o3WUZoS0R1NlhjUiJ9.eyJzY29wZSI6Im9wZW5pZF9sZWFyY3JlZGVudGlhbCIsImlzcyI6ImRpZDprZXk6ekRuYWVVY1c3cEFWMnhmY0VNUnNpM3RzZ1lTWWtMRWY4bWJTQ1o3WUZoS0R1NlhjUiIsInJlc3BvbnNlX3R5cGUiOiJjb2RlIiwicmVkaXJlY3RfdXJpIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgxL2NiIiwiZXhwIjoxNzU4MTkzNjEyLCJpYXQiOjE3MjcwODk2MTIsImNsaWVudF9pZCI6ImRpZDprZXk6ekRuYWVVY1c3cEFWMnhmY0VNUnNpM3RzZ1lTWWtMRWY4bWJTQ1o3WUZoS0R1NlhjUiJ9.9QoanrjKyIOLQpQ3rj2ucUzwJa6XH1T5-pabnAjYmJmyl5lNSG1v0y5vEvTLlYugrrwUjxnv9tsbqXfirz6kMQ";
//        // Simulación de la respuesta HTTP con código 200 y el JWT en el cuerpo
//        // Simulamos el comportamiento del HttpClient cuando se hace la llamada
//        // Simulación de una respuesta con código 200 y el JWT en el body
//        HttpResponse<String> mockHttpResponse = mock(HttpResponse.class);
//        when(mockHttpResponse.statusCode()).thenReturn(200);  // Simulamos código 200
//        when(mockHttpResponse.body()).thenReturn(jwt);  // El cuerpo contiene el JWT
//
//        // Simulamos el comportamiento del HttpClient cuando se hace la llamada
//        HttpClient mockHttpClient = mock(HttpClient.class);
//        when(mockHttpClient.send(any(HttpRequest.class), eq(HttpResponse.BodyHandlers.ofString())))
//                .thenReturn(mockHttpResponse);  // Mockeamos que retorne el mockHttpResponse con el JWT
//
//        // Action
//        Exception exception = assertThrows(OAuth2AuthorizationCodeRequestAuthenticationException.class, () ->
//                customAuthorizationRequestConverter.convert(mockRequest));
//
//    }

}
