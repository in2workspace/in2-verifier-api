package es.in2.vcverifier.security.filters;

import es.in2.vcverifier.exception.RequestMismatchException;
import es.in2.vcverifier.exception.RequestObjectRetrievalException;
import es.in2.vcverifier.service.HttpClientService;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.net.http.HttpResponse;
import java.util.Set;

import static es.in2.vcverifier.util.Constants.REQUEST_URI;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CustomAuthorizationRequestConverterTest {

    @Mock
    private HttpServletRequest httpServletRequest;

    @Mock
    private RegisteredClientRepository registeredClientRepository;

    @Mock
    private HttpClientService httpClientService;

    @Mock
    private HttpResponse<String> httpResponse; // Uso este Mock a nivel de clase

    @InjectMocks
    private CustomAuthorizationRequestConverter customAuthorizationRequestConverter;

    @Test
    void convert_WithNullRequestUri_ShouldThrowUnsupportedScopeException() {
        String clientId = "valid-client-id";
        String state = "valid-state";
        String unsupportedScope = "invalid-scope";

        when(httpServletRequest.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(clientId);
        when(httpServletRequest.getParameter(REQUEST_URI)).thenReturn(null);
        when(httpServletRequest.getParameter(OAuth2ParameterNames.SCOPE)).thenReturn(unsupportedScope);
        when(httpServletRequest.getParameter(OAuth2ParameterNames.STATE)).thenReturn(state);

        when(registeredClientRepository.findByClientId(clientId)).thenReturn(null);

        assertThrows(IllegalArgumentException.class, () -> customAuthorizationRequestConverter.convert(httpServletRequest));
    }

    @Test
    void convert_WithoutClientId_ShouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> customAuthorizationRequestConverter.convert(httpServletRequest));
    }

//    @Test
//    void convert_WhenRequestUriIsProvided_ShouldRetrieveAndVerifyJwt() throws Exception {
//        // Setup: Simulación de HttpServletRequest
//        String requestUri = "https://example.com/jwt/1234";
//        String clientId = "did:key:zDnaeUcW7pAV2xfcEMRsi3tsgYSYkLEf8mbSCZ7YFhKDu6XcR";
//        String state = "valid-state";
//        String scope = "openid learcredential";
//        String redirectUri = "https://redirect.com";
//
//        // Mockear los parámetros del request
//        when(httpServletRequest.getParameter(REQUEST_URI)).thenReturn(requestUri);
//        when(httpServletRequest.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(clientId);
//        when(httpServletRequest.getParameter(OAuth2ParameterNames.STATE)).thenReturn(state);
//        when(httpServletRequest.getParameter(OAuth2ParameterNames.SCOPE)).thenReturn(scope);
//        when(httpServletRequest.getParameter(OAuth2ParameterNames.REDIRECT_URI)).thenReturn(redirectUri);
//
//        // Simulación de un JWT válido en la respuesta HTTP
//        String jwt = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkaWQiLCJjbGllbnRfaWQiOiJkaWQ6a2V5OmZvb2JhciJ9.9xFGQjZHOdsJIOQa1234";
//
//        // Aquí estamos utilizando el mock global para la respuesta HTTP
//        when(httpResponse.body()).thenReturn(jwt);
//        when(httpClientService.performGetRequest(requestUri)).thenReturn(httpResponse); // Llamada a la URL mockeada
//
//        // Mockear el repositorio de RegisteredClient
//        RegisteredClient registeredClient = mock(RegisteredClient.class);
//        when(registeredClient.getRedirectUris()).thenReturn(Set.of(redirectUri));
//        when(registeredClientRepository.findByClientId(clientId)).thenReturn(registeredClient);
//
//        // Acción: Llamar al convert
//        Authentication authentication = customAuthorizationRequestConverter.convert(httpServletRequest);
//
//        // Verificación: Asegurar que se obtuvo autenticación y que tiene el cliente correcto
//        assertNotNull(authentication);
//        assertEquals(clientId, authentication.getPrincipal());
//    }
//
//    @Test
//    void convert_WhenRequestUriReturnsError_ShouldThrowRequestObjectRetrievalException() {
//        // Setup: Simulación de HttpServletRequest
//        String requestUri = "https://example.com/jwt/invalid";
//        String clientId = "did:key:zDnaeUcW7pAV2xfcEMRsi3tsgYSYkLEf8mbSCZ7YFhKDu6XcR";
//        String state = "valid-state";
//        String scope = "openid learcredential";
//        String redirectUri = "https://redirect.com";
//
//        when(httpServletRequest.getParameter(REQUEST_URI)).thenReturn(requestUri);
//        when(httpServletRequest.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(clientId);
//        when(httpServletRequest.getParameter(OAuth2ParameterNames.STATE)).thenReturn(state);
//        when(httpServletRequest.getParameter(OAuth2ParameterNames.SCOPE)).thenReturn(scope);
//        when(httpServletRequest.getParameter(OAuth2ParameterNames.REDIRECT_URI)).thenReturn(redirectUri);
//
//        // Simulación de una respuesta de error (404 Not Found)
//        when(httpResponse.statusCode()).thenReturn(404); // Simular código de estado 404
//        when(httpClientService.performGetRequest(requestUri)).thenReturn(httpResponse);
//
//        // Mockear el repositorio de RegisteredClient
//        RegisteredClient registeredClient = mock(RegisteredClient.class);
//        when(registeredClient.getRedirectUris()).thenReturn(Set.of(redirectUri));
//        when(registeredClientRepository.findByClientId(clientId)).thenReturn(registeredClient);
//
//        // Acción y verificación: Llamar al método y verificar que lanza una excepción de RequestObjectRetrievalException
//        assertThrows(RequestObjectRetrievalException.class, () -> customAuthorizationRequestConverter.convert(httpServletRequest));
//    }
//
//    @Test
//    void convert_WhenOAuth2ParametersDoNotMatch_ShouldThrowRequestMismatchException() throws Exception {
//        // Setup: Simulación de HttpServletRequest
//        String requestUri = "https://example.com/jwt/1234";
//        String clientId = "did:key:zDnaeUcW7pAV2xfcEMRsi3tsgYSYkLEf8mbSCZ7YFhKDu6XcR";
//        String state = "valid-state";
//        String scope = "openid learcredential";
//        String redirectUri = "https://redirect.com";
//
//        when(httpServletRequest.getParameter(REQUEST_URI)).thenReturn(requestUri);
//        when(httpServletRequest.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(clientId);
//        when(httpServletRequest.getParameter(OAuth2ParameterNames.STATE)).thenReturn(state);
//        when(httpServletRequest.getParameter(OAuth2ParameterNames.SCOPE)).thenReturn(scope);
//        when(httpServletRequest.getParameter(OAuth2ParameterNames.REDIRECT_URI)).thenReturn(redirectUri);
//
//        // Simulación de un JWT con parámetros diferentes
//        String jwt = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkaWQiLCJjbGllbnRfaWQiOiJkaWQ6a2V5OmZvb2JhciIsInNjb3BlIjoiYmFkX3Njb3BlIn0.9xFGQjZHOdsJIOQa1234";
//        when(httpResponse.body()).thenReturn(jwt);
//        when(httpClientService.performGetRequest(requestUri)).thenReturn(httpResponse);
//
//        // Mockear el repositorio de RegisteredClient
//        RegisteredClient registeredClient = mock(RegisteredClient.class);
//        when(registeredClient.getRedirectUris()).thenReturn(Set.of(redirectUri));
//        when(registeredClientRepository.findByClientId(clientId)).thenReturn(registeredClient);
//
//        // Acción y verificación: Llamar al método y verificar que lanza una RequestMismatchException
//        assertThrows(RequestMismatchException.class, () -> customAuthorizationRequestConverter.convert(httpServletRequest));
//    }

//    @Test
//    void convert_WhenRedirectUriIsInvalid_ShouldThrowIllegalArgumentException() {
//        // Setup: Simulación de HttpServletRequest
//        String requestUri = "https://example.com/jwt/1234";
//        String clientId = "did:key:zDnaeUcW7pAV2xfcEMRsi3tsgYSYkLEf8mbSCZ7YFhKDu6XcR";
//        String state = "valid-state";
//        String scope = "openid learcredential";
//        String redirectUri = "https://invalid-redirect.com";
//
//        when(httpServletRequest.getParameter(REQUEST_URI)).thenReturn(requestUri);
//        when(httpServletRequest.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(clientId);
//        when(httpServletRequest.getParameter(OAuth2ParameterNames.STATE)).thenReturn(state);
//        when(httpServletRequest.getParameter(OAuth2ParameterNames.SCOPE)).thenReturn(scope);
//        when(httpServletRequest.getParameter(OAuth2ParameterNames.REDIRECT_URI)).thenReturn(redirectUri);
//
//        // Mockear el repositorio de RegisteredClient con un redirect_uri diferente
//        RegisteredClient registeredClient = mock(RegisteredClient.class);
//        when(registeredClient.getRedirectUris()).thenReturn(Set.of("https://valid-redirect.com"));
//        when(registeredClientRepository.findByClientId(clientId)).thenReturn(registeredClient);
//
//        // Acción y verificación: Llamar al método y verificar que lanza una excepción de IllegalArgumentException
//        assertThrows(IllegalArgumentException.class, () -> customAuthorizationRequestConverter.convert(httpServletRequest));
//    }

}

