package es.in2.vcverifier.security.filters;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CustomAuthorizationRequestConverterTest {

    @Mock
    private HttpServletRequest httpServletRequest;

    @Mock
    private RegisteredClientRepository registeredClientRepository;

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

        when(registeredClientRepository.findByClientId(clientId)).thenReturn(null);

        assertThrows(IllegalArgumentException.class, () -> customAuthorizationRequestConverter.convert(httpServletRequest));
    }

    @Test
    void convert_WithoutClientId_ShouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> customAuthorizationRequestConverter.convert(httpServletRequest));
    }

}
