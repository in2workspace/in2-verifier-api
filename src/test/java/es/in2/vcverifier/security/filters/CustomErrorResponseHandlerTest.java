package es.in2.vcverifier.security.filters;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;

import java.io.IOException;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CustomErrorResponseHandlerTest {

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @InjectMocks
    private CustomErrorResponseHandler customErrorResponseHandler;

    @Test
    void testOnAuthenticationFailure_WithOAuth2Exception_AndUriPresent() throws IOException {
        String redirectUri = "https://example.com/error";
        OAuth2Error oauth2Error = new OAuth2Error("invalid_request", "Invalid request", redirectUri);
        AuthenticationException exception = new OAuth2AuthorizationCodeRequestAuthenticationException(oauth2Error, null);

        customErrorResponseHandler.onAuthenticationFailure(request, response, exception);

        verify(response).sendRedirect(redirectUri);
        verify(response, never()).sendError(HttpServletResponse.SC_BAD_REQUEST, "Authentication failed");
    }

    @Test
    void testOnAuthenticationFailure_WithOAuth2Exception_WithoutUri() throws IOException {
        OAuth2Error oauth2Error = new OAuth2Error("invalid_request", "Invalid request", null);
        AuthenticationException exception = new OAuth2AuthorizationCodeRequestAuthenticationException(oauth2Error, null);

        customErrorResponseHandler.onAuthenticationFailure(request, response, exception);

        verify(response, never()).sendRedirect(anyString());
        verify(response).sendError(HttpServletResponse.SC_BAD_REQUEST, "Authentication failed");
    }

    @Test
    void testOnAuthenticationFailure_WithOtherAuthenticationException() throws IOException {
        AuthenticationException exception = mock(AuthenticationException.class);

        customErrorResponseHandler.onAuthenticationFailure(request, response, exception);

        verify(response, never()).sendRedirect(anyString());
        verify(response).sendError(HttpServletResponse.SC_BAD_REQUEST, "Authentication failed");
    }

}
