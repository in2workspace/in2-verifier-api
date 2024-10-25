package es.in2.vcverifier.security.filters;

import es.in2.vcverifier.config.CacheStore;
import es.in2.vcverifier.component.CryptoComponent;
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

import java.net.http.HttpClient;
import java.net.http.HttpResponse;

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

}
