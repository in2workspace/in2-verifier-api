package es.in2.verifier.security.filters;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.verifier.config.properties.SecurityProperties;
import es.in2.verifier.model.credentials.Issuer;
import es.in2.verifier.model.credentials.dome.CredentialSubject;
import es.in2.verifier.model.credentials.dome.Mandate;
import es.in2.verifier.model.credentials.dome.Mandatee;
import es.in2.verifier.model.credentials.dome.employee.LEARCredentialEmployee;
import es.in2.verifier.model.credentials.dome.machine.LEARCredentialMachine;
import es.in2.verifier.service.JWTService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CustomAuthenticationProviderTest {

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

    @Test
    void authenticate_validAuthorizationCodeGrant_withEmployeeCredential_success() throws Exception {
        // Arrange
        String clientId = "test-client-id";
        String audience = "test-audience";
        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put("client_id", clientId);

        // Configure the verifiable credential (VC) map
        Map<String, Object> vcMap = new HashMap<>();
        vcMap.put("type", List.of("VerifiableCredential", "LEARCredentialEmployee"));



        additionalParameters.put("vc", vcMap);
        additionalParameters.put(OAuth2ParameterNames.AUDIENCE, audience);
        additionalParameters.put(OAuth2ParameterNames.SCOPE, "openid profile email");

        OAuth2AuthorizationCodeAuthenticationToken authenticationToken = mock(OAuth2AuthorizationCodeAuthenticationToken.class);
        when(authenticationToken.getAdditionalParameters()).thenReturn(additionalParameters);

        RegisteredClient registeredClient = mock(RegisteredClient.class);
        when(registeredClientRepository.findByClientId(clientId)).thenReturn(registeredClient);

        SecurityProperties.TokenProperties tokenProperties = mock(SecurityProperties.TokenProperties.class);
        SecurityProperties.TokenProperties.AccessTokenProperties accessTokenProperties = mock(SecurityProperties.TokenProperties.AccessTokenProperties.class);
        SecurityProperties.TokenProperties.IdTokenProperties idTokenProperties = mock(SecurityProperties.TokenProperties.IdTokenProperties.class);

        when(securityProperties.token()).thenReturn(tokenProperties);
        when(tokenProperties.accessToken()).thenReturn(accessTokenProperties);
        when(accessTokenProperties.expiration()).thenReturn("3600");
        when(accessTokenProperties.cronUnit()).thenReturn("SECONDS");
        when(tokenProperties.idToken()).thenReturn(idTokenProperties);
        when(idTokenProperties.expiration()).thenReturn("3600");
        when(idTokenProperties.cronUnit()).thenReturn("SECONDS");
        when(securityProperties.authorizationServer()).thenReturn("https://auth.server");

        JsonNode vcJsonNode = mock(JsonNode.class);
        when(objectMapper.convertValue(vcMap, JsonNode.class)).thenReturn(vcJsonNode);

        LEARCredentialEmployee learCredentialEmployee = getLEARCredentialEmployee();

        when(objectMapper.convertValue(vcJsonNode, LEARCredentialEmployee.class)).thenReturn(learCredentialEmployee);

        when(objectMapper.writeValueAsString(learCredentialEmployee)).thenReturn("{\"credential\":\"value\"}");

        when(jwtService.generateJWT(anyString())).thenReturn("mock-jwt-token");

        Authentication result = customAuthenticationProvider.authenticate(authenticationToken);

        assertNotNull(result);
        assertInstanceOf(OAuth2AccessTokenAuthenticationToken.class, result);

        OAuth2AccessTokenAuthenticationToken tokenResult = (OAuth2AccessTokenAuthenticationToken) result;
        assertEquals("mock-jwt-token", tokenResult.getAccessToken().getTokenValue());

        Map<String, Object> additionalParams = tokenResult.getAdditionalParameters();
        assertTrue(additionalParams.containsKey("id_token"));
        assertEquals("mock-jwt-token", additionalParams.get("id_token"));

        verify(jwtService, times(2)).generateJWT(anyString());
    }


    @Test
    void authenticate_validClientCredentialsGrant_withMachineCredential_success() throws Exception {
        // Arrange
        String clientId = "test-client-id";
        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put("client_id", clientId);

        Map<String, Object> vcMap = new HashMap<>();
        vcMap.put("type", List.of("VerifiableCredential", "LEARCredentialMachine"));

        additionalParameters.put("vc", vcMap);
        additionalParameters.put(OAuth2ParameterNames.SCOPE, "machine");

        OAuth2ClientCredentialsAuthenticationToken authenticationToken = mock(OAuth2ClientCredentialsAuthenticationToken.class);
        when(authenticationToken.getAdditionalParameters()).thenReturn(additionalParameters);

        RegisteredClient registeredClient = mock(RegisteredClient.class);
        when(registeredClientRepository.findByClientId(clientId)).thenReturn(registeredClient);

        SecurityProperties.TokenProperties tokenProperties = mock(SecurityProperties.TokenProperties.class);
        SecurityProperties.TokenProperties.AccessTokenProperties accessTokenProperties = mock(SecurityProperties.TokenProperties.AccessTokenProperties.class);
        SecurityProperties.TokenProperties.IdTokenProperties idTokenProperties = mock(SecurityProperties.TokenProperties.IdTokenProperties.class);

        when(securityProperties.token()).thenReturn(tokenProperties);
        when(tokenProperties.accessToken()).thenReturn(accessTokenProperties);
        when(accessTokenProperties.expiration()).thenReturn("3600");
        when(accessTokenProperties.cronUnit()).thenReturn("SECONDS");
        when(tokenProperties.idToken()).thenReturn(idTokenProperties);
        when(idTokenProperties.expiration()).thenReturn("3600");
        when(idTokenProperties.cronUnit()).thenReturn("SECONDS");
        when(securityProperties.authorizationServer()).thenReturn("https://auth.server");

        JsonNode vcJsonNode = mock(JsonNode.class);
        when(objectMapper.convertValue(vcMap, JsonNode.class)).thenReturn(vcJsonNode);

        LEARCredentialMachine credential = getLEARCredentialMachine();
        when(objectMapper.convertValue(vcJsonNode, LEARCredentialMachine.class)).thenReturn(credential);

        when(jwtService.generateJWT(anyString())).thenReturn("mock-jwt-token");

        // Act
        Authentication result = customAuthenticationProvider.authenticate(authenticationToken);

        // Assert
        assertNotNull(result);
        assertInstanceOf(OAuth2AccessTokenAuthenticationToken.class, result);

        OAuth2AccessTokenAuthenticationToken tokenResult = (OAuth2AccessTokenAuthenticationToken) result;
        assertEquals("mock-jwt-token", tokenResult.getAccessToken().getTokenValue());

        verify(jwtService, times(2)).generateJWT(anyString());
    }


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
    void authenticate_withProfileAndEmailScopes_addsCorrespondingClaims() throws Exception {
        // Given
        String clientId = "test-client-id";
        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put("vc", new HashMap<>());
        additionalParameters.put("client_id", clientId);
        additionalParameters.put("audience", "test-audience");
        additionalParameters.put(OAuth2ParameterNames.SCOPE, "openid profile email");

        // Mock the authentication token
        OAuth2AuthorizationCodeAuthenticationToken auth = mock(OAuth2AuthorizationCodeAuthenticationToken.class);
        when(auth.getAdditionalParameters()).thenReturn(additionalParameters);

        // Mock the registered client
        RegisteredClient registeredClient = mock(RegisteredClient.class);
        when(registeredClientRepository.findByClientId(clientId)).thenReturn(registeredClient);

        // Mock security properties
        SecurityProperties.TokenProperties tokenProperties = mock(SecurityProperties.TokenProperties.class);
        SecurityProperties.TokenProperties.AccessTokenProperties accessTokenProperties = mock(SecurityProperties.TokenProperties.AccessTokenProperties.class);
        SecurityProperties.TokenProperties.IdTokenProperties idTokenProperties = mock(SecurityProperties.TokenProperties.IdTokenProperties.class);

        when(securityProperties.token()).thenReturn(tokenProperties);
        when(tokenProperties.accessToken()).thenReturn(accessTokenProperties);
        when(accessTokenProperties.expiration()).thenReturn("3600");
        when(accessTokenProperties.cronUnit()).thenReturn("SECONDS");
        when(tokenProperties.idToken()).thenReturn(idTokenProperties);
        when(idTokenProperties.expiration()).thenReturn("3600");
        when(idTokenProperties.cronUnit()).thenReturn("SECONDS");
        when(securityProperties.authorizationServer()).thenReturn("https://auth.server");

        // Mock the verifiable credential
        JsonNode jsonNode = mock(JsonNode.class);
        when(objectMapper.convertValue(additionalParameters.get("vc"), JsonNode.class)).thenReturn(jsonNode);

        LEARCredentialEmployee credential = getLEARCredentialEmployee();
        when(objectMapper.convertValue(any(), eq(LEARCredentialEmployee.class))).thenReturn(credential);

        // Mock objectMapper.writeValueAsString
        when(objectMapper.writeValueAsString(any())).thenReturn("{\"credential\":\"value\"}");

        // Capture the arguments passed to jwtService.generateJWT
        ArgumentCaptor<String> jwtPayloadCaptor = ArgumentCaptor.forClass(String.class);
        when(jwtService.generateJWT(jwtPayloadCaptor.capture())).thenReturn("mock-jwt-token");

        // When
        Authentication result = customAuthenticationProvider.authenticate(auth);

        // Then
        assertNotNull(result);
        assertInstanceOf(OAuth2AccessTokenAuthenticationToken.class, result);

        OAuth2AccessTokenAuthenticationToken tokenResult = (OAuth2AccessTokenAuthenticationToken) result;
        assertEquals("mock-jwt-token", tokenResult.getAccessToken().getTokenValue());

        Map<String, Object> additionalParams = tokenResult.getAdditionalParameters();
        assertTrue(additionalParams.containsKey("id_token"));
        assertEquals("mock-jwt-token", additionalParams.get("id_token"));

        // Verify that jwtService.generateJWT was called twice (Access Token and ID Token)
        verify(jwtService, times(2)).generateJWT(any());

        // Parse the captured payload for ID Token
        List<String> capturedPayloads = jwtPayloadCaptor.getAllValues();
        assertEquals(2, capturedPayloads.size());

        String idTokenPayloadString = capturedPayloads.get(1); // Assuming second call is for ID Token
        ObjectMapper objectMapperUtil = new ObjectMapper();
        Map<String, Object> idTokenClaims = objectMapperUtil.readValue(idTokenPayloadString, Map.class);

        // Verify claims based on scopes
        assertEquals("did:key:1234", idTokenClaims.get("sub"));
        assertEquals("https://auth.server", idTokenClaims.get("iss"));

        // Verify profile claims
        assertEquals("John Doe", idTokenClaims.get("name"));
        assertEquals("John", idTokenClaims.get("given_name"));
        assertEquals("Doe", idTokenClaims.get("family_name"));

        // Verify email claims
        assertEquals("john.doe@example.com", idTokenClaims.get("email"));
        assertEquals(true, idTokenClaims.get("email_verified"));
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
        Mandatee mandatee = Mandatee.builder()
                .id("did:key:1234")
                .firstName("John")
                .lastName("Doe")
                .email("john.doe@example.com")
                .build();
        Mandate mandate = Mandate.builder()
                .mandatee(mandatee)
                .build();
        CredentialSubject credentialSubject = CredentialSubject.builder()
                .mandate(mandate)
                .build();
        return LEARCredentialEmployee.builder()
                .type(List.of("VerifiableCredential", "LEARCredentialEmployee"))
                .context(List.of("https://www.w3.org/2018/credentials/v1"))
                .id("urn:uuid:1234")
                .issuer("did:elsi:issuer")
                .credentialSubject(credentialSubject)
                .build();
    }

    private LEARCredentialMachine getLEARCredentialMachine(){
        Mandatee mandateeLCEmployee = Mandatee.builder().id("mandatee-id").build();
        Mandate mandateLCEmployee = Mandate.builder().mandatee(mandateeLCEmployee).build();
        CredentialSubject credentialSubject = new CredentialSubject(mandateLCEmployee);

        return LEARCredentialMachine.builder()
                .credentialSubject(credentialSubject)
                .context(List.of("https://www.w3.org/2018/credentials/v1"))
                .id("urn:uuid:1234")
                .issuer(Issuer.builder()
                        .id("did:elsi:issuer")
                        .build())
                .type(List.of("VerifiableCredential", "LEARCredentialMachine"))
                .build();
    }


}
