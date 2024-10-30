package es.in2.vcverifier.security.filters;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.ECKey;
import es.in2.vcverifier.config.properties.SecurityProperties;
import es.in2.vcverifier.component.CryptoComponent;
import es.in2.vcverifier.model.credentials.employee.*;
import es.in2.vcverifier.model.credentials.machine.CredentialSubjectLCMachine;
import es.in2.vcverifier.model.credentials.machine.LEARCredentialMachine;
import es.in2.vcverifier.model.credentials.machine.MandateLCMachine;
import es.in2.vcverifier.model.credentials.machine.MandateeLCMachine;
import es.in2.vcverifier.service.JWTService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CustomAuthenticationProviderTest {

    @Mock
    private CryptoComponent cryptoComponent;

    @Mock
    private JWTService jwtService;

    @Mock
    private RegisteredClientRepository registeredClientRepository;

    @Mock
    private SecurityProperties securityProperties;

    @Mock
    private ObjectMapper objectMapper;

    @InjectMocks
    private CustomAuthenticationProvider customAuthenticationProvider;

//    @Test
//    void authenticate_validCodeGrant_success_With_LEARCredentialEmployee() {
//        String clientId = "test-client-id";
//        Map<String, Object> additionalParameters = new HashMap<>();
//        additionalParameters.put("vc", new HashMap<>());
//        additionalParameters.put("client_id", clientId);
//        additionalParameters.put("audience", "test-audience");
//
//        OAuth2AuthorizationCodeAuthenticationToken auth = mock(OAuth2AuthorizationCodeAuthenticationToken.class);
//        when(auth.getAdditionalParameters()).thenReturn(additionalParameters);
//
//        RegisteredClient registeredClient = mock(RegisteredClient.class);
//        when(registeredClientRepository.findByClientId(clientId)).thenReturn(registeredClient);
//        when(securityProperties.token()).thenReturn(mock(SecurityProperties.TokenProperties.class));
//        when(securityProperties.token().accessToken()).thenReturn(mock(SecurityProperties.TokenProperties.AccessTokenProperties.class));
//        when(securityProperties.token().accessToken().expiration()).thenReturn("3600");
//        when(securityProperties.token().accessToken().cronUnit()).thenReturn("SECONDS");
//
//        JsonNode jsonNode = mock(JsonNode.class);
//        when(objectMapper.convertValue(additionalParameters.get("vc"), JsonNode.class)).thenReturn(jsonNode);
//
//        LEARCredentialEmployee credential = getLEARCredentialEmployee();
//        when(objectMapper.convertValue(any(), eq(LEARCredentialEmployee.class))).thenReturn(credential);
//
//        String jwtToken = "mock-jwt-token";
//        when(jwtService.generateJWT(any())).thenReturn(jwtToken);
//
//        when(cryptoComponent.getECKey()).thenReturn(mock(ECKey.class));
//        when(cryptoComponent.getECKey().getKeyID()).thenReturn("mock-key-id");
//
//        Authentication result = customAuthenticationProvider.authenticate(auth);
//
//        assertNotNull(result);
//        assertInstanceOf(OAuth2AccessTokenAuthenticationToken.class, result);
//
//        OAuth2AccessToken accessToken = ((OAuth2AccessTokenAuthenticationToken) result).getAccessToken();
//        assertEquals(jwtToken, accessToken.getTokenValue());
//        assertEquals(OAuth2AccessToken.TokenType.BEARER, accessToken.getTokenType());
//    }
//
//    @Test
//    void authenticate_validCodeGrant_success_With_LEARCredentialMachine() {
//        String clientId = "test-client-id";
//        Map<String, Object> additionalParameters = new HashMap<>();
//        additionalParameters.put("vc", new HashMap<>());
//        additionalParameters.put("client_id", clientId);
//        additionalParameters.put("audience", "test-audience");
//
//        OAuth2ClientCredentialsAuthenticationToken auth = mock(OAuth2ClientCredentialsAuthenticationToken.class);
//        when(auth.getAdditionalParameters()).thenReturn(additionalParameters);
//
//        RegisteredClient registeredClient = mock(RegisteredClient.class);
//        when(registeredClientRepository.findByClientId(clientId)).thenReturn(registeredClient);
//        when(securityProperties.token()).thenReturn(mock(SecurityProperties.TokenProperties.class));
//        when(securityProperties.token().accessToken()).thenReturn(mock(SecurityProperties.TokenProperties.AccessTokenProperties.class));
//        when(securityProperties.token().accessToken().expiration()).thenReturn("3600");
//        when(securityProperties.token().accessToken().cronUnit()).thenReturn("SECONDS");
//
//        JsonNode jsonNode = mock(JsonNode.class);
//        when(objectMapper.convertValue(additionalParameters.get("vc"), JsonNode.class)).thenReturn(jsonNode);
//
//        LEARCredentialMachine credential = getLEARCredentialMachine();
//        when(objectMapper.convertValue(any(), eq(LEARCredentialMachine.class))).thenReturn(credential);
//
//        String jwtToken = "mock-jwt-token";
//        when(jwtService.generateJWT(any())).thenReturn(jwtToken);
//
//        when(cryptoComponent.getECKey()).thenReturn(mock(ECKey.class));
//        when(cryptoComponent.getECKey().getKeyID()).thenReturn("mock-key-id");
//
//        Authentication result = customAuthenticationProvider.authenticate(auth);
//
//        assertNotNull(result);
//        assertInstanceOf(OAuth2AccessTokenAuthenticationToken.class, result);
//
//        OAuth2AccessToken accessToken = ((OAuth2AccessTokenAuthenticationToken) result).getAccessToken();
//        assertEquals(jwtToken, accessToken.getTokenValue());
//        assertEquals(OAuth2AccessToken.TokenType.BEARER, accessToken.getTokenType());
//    }

    @Test
    void authenticate_throw_OAuth2AuthenticationException() {
        Authentication invalidAuthentication = new UsernamePasswordAuthenticationToken("user", "password");

        OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class, () -> customAuthenticationProvider.authenticate(invalidAuthentication));

        assertEquals(OAuth2ErrorCodes.UNSUPPORTED_GRANT_TYPE, exception.getError().getErrorCode());
    }

    @Test
    void authenticate_OAuth2ClientCredentialsAuthenticationToken_with_null_additional_parameters_throw_OAuth2AuthenticationException() {

        OAuth2ClientCredentialsAuthenticationToken auth = mock(OAuth2ClientCredentialsAuthenticationToken.class);
        when(auth.getAdditionalParameters()).thenReturn(null);

        OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class, () -> customAuthenticationProvider.authenticate(auth));

        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, exception.getError().getErrorCode());
    }

    @Test
    void authenticate_OAuth2AuthorizationCodeAuthenticationToken_with_null_additional_parameters_throw_OAuth2AuthenticationException() {

        OAuth2AuthorizationCodeAuthenticationToken auth = mock(OAuth2AuthorizationCodeAuthenticationToken.class);
        when(auth.getAdditionalParameters()).thenReturn(null);

        OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class, () -> customAuthenticationProvider.authenticate(auth));

        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, exception.getError().getErrorCode());
    }

    @Test
    void authenticate_OAuth2ClientCredentialsAuthenticationToken_without_clientId_parameter_throw_OAuth2AuthenticationException() {
        Map<String, Object> additionalParameters = new HashMap<>();

        OAuth2ClientCredentialsAuthenticationToken auth = mock(OAuth2ClientCredentialsAuthenticationToken.class);
        when(auth.getAdditionalParameters()).thenReturn(additionalParameters);

        OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class, () -> customAuthenticationProvider.authenticate(auth));

        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, exception.getError().getErrorCode());
    }

    @Test
    void authenticate_OAuth2AuthorizationCodeAuthenticationToken_without_clientId_parameter_throw_OAuth2AuthenticationException() {
        Map<String, Object> additionalParameters = new HashMap<>();

        OAuth2AuthorizationCodeAuthenticationToken auth = mock(OAuth2AuthorizationCodeAuthenticationToken.class);
        when(auth.getAdditionalParameters()).thenReturn(additionalParameters);

        OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class, () -> customAuthenticationProvider.authenticate(auth));

        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, exception.getError().getErrorCode());
    }

    @Test
    void authenticate_OAuth2ClientCredentialsAuthenticationToken_with_invalid_registered_client_throw_OAuth2AuthenticationException() {
        String clientId = "test-client-id";
        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put("client_id", clientId);

        OAuth2ClientCredentialsAuthenticationToken auth = mock(OAuth2ClientCredentialsAuthenticationToken.class);
        when(auth.getAdditionalParameters()).thenReturn(additionalParameters);

        when(registeredClientRepository.findByClientId(clientId)).thenReturn(null);

        OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class, () -> customAuthenticationProvider.authenticate(auth));

        assertEquals(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT, exception.getError().getErrorCode());
    }

    @Test
    void authenticate_OAuth2AuthorizationCodeAuthenticationToken_with_invalid_registered_client_throw_OAuth2AuthenticationException() {
        String clientId = "test-client-id";
        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put("client_id", clientId);

        OAuth2AuthorizationCodeAuthenticationToken auth = mock(OAuth2AuthorizationCodeAuthenticationToken.class);
        when(auth.getAdditionalParameters()).thenReturn(additionalParameters);

        when(registeredClientRepository.findByClientId(clientId)).thenReturn(null);

        OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class, () -> customAuthenticationProvider.authenticate(auth));

        assertEquals(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT, exception.getError().getErrorCode());
    }

    @Test
    void authenticate_OAuth2ClientCredentialsAuthenticationToken_without_vc_parameter_throw_OAuth2AuthenticationException() {
        String clientId = "test-client-id";
        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put("client_id", clientId);

        OAuth2ClientCredentialsAuthenticationToken auth = mock(OAuth2ClientCredentialsAuthenticationToken.class);
        when(auth.getAdditionalParameters()).thenReturn(additionalParameters);

        RegisteredClient registeredClient = mock(RegisteredClient.class);
        when(registeredClientRepository.findByClientId(clientId)).thenReturn(registeredClient);
        when(securityProperties.token()).thenReturn(mock(SecurityProperties.TokenProperties.class));
        when(securityProperties.token().accessToken()).thenReturn(mock(SecurityProperties.TokenProperties.AccessTokenProperties.class));
        when(securityProperties.token().accessToken().expiration()).thenReturn("3600");
        when(securityProperties.token().accessToken().cronUnit()).thenReturn("SECONDS");

        OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class, () -> customAuthenticationProvider.authenticate(auth));

        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, exception.getError().getErrorCode());

    }

    @Test
    void authenticate_OAuth2AuthorizationCodeAuthenticationToken_without_vc_parameter_throw_OAuth2AuthenticationException() {
        String clientId = "test-client-id";
        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put("client_id", clientId);

        OAuth2AuthorizationCodeAuthenticationToken auth = mock(OAuth2AuthorizationCodeAuthenticationToken.class);
        when(auth.getAdditionalParameters()).thenReturn(additionalParameters);

        RegisteredClient registeredClient = mock(RegisteredClient.class);
        when(registeredClientRepository.findByClientId(clientId)).thenReturn(registeredClient);
        when(securityProperties.token()).thenReturn(mock(SecurityProperties.TokenProperties.class));
        when(securityProperties.token().accessToken()).thenReturn(mock(SecurityProperties.TokenProperties.AccessTokenProperties.class));
        when(securityProperties.token().accessToken().expiration()).thenReturn("3600");
        when(securityProperties.token().accessToken().cronUnit()).thenReturn("SECONDS");

        OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class, () -> customAuthenticationProvider.authenticate(auth));

        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, exception.getError().getErrorCode());

    }

    @Test
    void authenticate_OAuth2AuthorizationCodeAuthenticationToken_without_audience_map_parameter_throws_OAuth2AuthenticationException() {
        String clientId = "test-client-id";
        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put("vc", new HashMap<>());
        additionalParameters.put("client_id", clientId);

        OAuth2AuthorizationCodeAuthenticationToken auth = mock(OAuth2AuthorizationCodeAuthenticationToken.class);
        when(auth.getAdditionalParameters()).thenReturn(additionalParameters);

        RegisteredClient registeredClient = mock(RegisteredClient.class);
        when(registeredClientRepository.findByClientId(clientId)).thenReturn(registeredClient);
        when(securityProperties.token()).thenReturn(mock(SecurityProperties.TokenProperties.class));
        when(securityProperties.token().accessToken()).thenReturn(mock(SecurityProperties.TokenProperties.AccessTokenProperties.class));
        when(securityProperties.token().accessToken().expiration()).thenReturn("3600");
        when(securityProperties.token().accessToken().cronUnit()).thenReturn("SECONDS");

        JsonNode jsonNode = mock(JsonNode.class);
        when(objectMapper.convertValue(additionalParameters.get("vc"), JsonNode.class)).thenReturn(jsonNode);

        LEARCredentialEmployee credential = getLEARCredentialEmployee();
        when(objectMapper.convertValue(any(), eq(LEARCredentialEmployee.class))).thenReturn(credential);


        OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class, () -> customAuthenticationProvider.authenticate(auth));

        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, exception.getError().getErrorCode());
    }

    @Test
    void supports_returnsTrue_forAuthorizationCodeAuthenticationToken() {
        boolean result = customAuthenticationProvider.supports(OAuth2AuthorizationCodeAuthenticationToken.class);
        assertTrue(result);
    }

    @Test
    void supports_returnsTrue_forClientCredentialsAuthenticationToken() {
        boolean result = customAuthenticationProvider.supports(OAuth2ClientCredentialsAuthenticationToken.class);
        assertTrue(result);
    }

    @Test
    void supports_returnsFalse_forOtherAuthenticationToken() {
        boolean result = customAuthenticationProvider.supports(OAuth2AccessTokenAuthenticationToken.class);
        assertFalse(result);
    }

    @Test
    void supports_returnsFalse_forNonAuthenticationClass() {
        boolean result = customAuthenticationProvider.supports(String.class);
        assertFalse(result);
    }


    private LEARCredentialEmployee getLEARCredentialEmployee(){
        MandateeLCEmployee mandateeLCEmployee = MandateeLCEmployee.builder().id("mandatee-id").build();
        MandateLCEmployee mandateLCEmployee = MandateLCEmployee.builder().mandatee(mandateeLCEmployee).build();
        CredentialSubjectLCEmployee credentialSubject = new CredentialSubjectLCEmployee(mandateLCEmployee);

        return LEARCredentialEmployee.builder()
                .credentialSubject(credentialSubject)
                .build();
    }

    private LEARCredentialMachine getLEARCredentialMachine(){
        MandateeLCMachine mandateeLCEmployee = MandateeLCMachine.builder().id("mandatee-id").build();
        MandateLCMachine mandateLCEmployee = MandateLCMachine.builder().mandatee(mandateeLCEmployee).build();
        CredentialSubjectLCMachine credentialSubject = new CredentialSubjectLCMachine(mandateLCEmployee);

        return LEARCredentialMachine.builder()
                .credentialSubject(credentialSubject)
                .build();
    }


}
