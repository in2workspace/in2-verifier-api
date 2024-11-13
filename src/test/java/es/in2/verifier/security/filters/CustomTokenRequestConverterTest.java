package es.in2.verifier.security.filters;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import es.in2.verifier.domain.filters.CustomTokenRequestConverter;
import es.in2.verifier.infrastructure.repository.CacheStore;
import es.in2.verifier.domain.exception.InvalidCredentialTypeException;
import es.in2.verifier.domain.exception.UnsupportedGrantTypeException;
import es.in2.verifier.domain.model.dto.AuthorizationCodeData;
import es.in2.verifier.domain.model.dto.credentials.machine.LEARCredentialMachine;
import es.in2.verifier.domain.model.enums.LEARCredentialType;
import es.in2.verifier.domain.service.ClientAssertionValidationService;
import es.in2.verifier.domain.service.JWTService;
import es.in2.verifier.domain.service.VpService;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.hibernate.validator.internal.util.Contracts.assertNotNull;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CustomTokenRequestConverterTest {

    @Mock
    private JWTService jwtService;

    @Mock
    private ClientAssertionValidationService clientAssertionValidationService;

    @Mock
    private VpService vpService;

    @Mock
    private CacheStore<AuthorizationCodeData> cacheStoreForAuthorizationCodeData;

    @Mock
    private OAuth2AuthorizationService oAuth2AuthorizationService;

    @Mock
    private ObjectMapper objectMapper;

    @InjectMocks
    private CustomTokenRequestConverter customTokenRequestConverter;

    @Test
    void convert_authorizationCodeGrant_shouldReturnOAuth2ClientCredentialsAuthenticationToken() {
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        Authentication clientPrincipal = mock(Authentication.class);
        SecurityContextHolder.getContext().setAuthentication(clientPrincipal);

        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.add(OAuth2ParameterNames.GRANT_TYPE, "authorization_code");
        parameters.add(OAuth2ParameterNames.CODE, "code");
        parameters.add(OAuth2ParameterNames.CLIENT_ID, "client-id");
        parameters.add(OAuth2ParameterNames.STATE, "state");

        when(mockRequest.getParameterMap()).thenReturn(convertToMap(parameters));

        AuthorizationCodeData authorizationCodeData = mock(AuthorizationCodeData.class);
        when(cacheStoreForAuthorizationCodeData.get("code")).thenReturn(authorizationCodeData);
        when(authorizationCodeData.state()).thenReturn("state");

        JsonNode jsonNodeMock = mock(JsonNode.class);
        when(authorizationCodeData.verifiableCredential()).thenReturn(jsonNodeMock);

        Authentication result = customTokenRequestConverter.convert(mockRequest);

        assertNotNull(result);
        assertInstanceOf(OAuth2AuthorizationCodeAuthenticationToken.class, result);

        verify(cacheStoreForAuthorizationCodeData).delete("code");
        verify(oAuth2AuthorizationService).remove(authorizationCodeData.oAuth2Authorization());
    }


    @Test
    void convert_clientCredentialsGrant_shouldReturnOAuth2ClientCredentialsAuthenticationToken() {
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        Authentication clientPrincipal = mock(Authentication.class);
        SecurityContextHolder.getContext().setAuthentication(clientPrincipal);

        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.add(OAuth2ParameterNames.GRANT_TYPE, "client_credentials");
        parameters.add(OAuth2ParameterNames.CLIENT_ID, "client-id");
        parameters.add(OAuth2ParameterNames.CLIENT_ASSERTION, "client-assertion");

        when(mockRequest.getParameterMap()).thenReturn(convertToMap(parameters));

        SignedJWT signedJWT = mock(SignedJWT.class);
        when(jwtService.parseJWT("client-assertion")).thenReturn(signedJWT);

        String vpToken = "vp-token";
        when(jwtService.getClaimFromPayload(any(), eq("vp_token"))).thenReturn(vpToken);

        JsonNode mockVC = mock(JsonNode.class);
        when(vpService.getCredentialFromTheVerifiablePresentationAsJsonNode(anyString())).thenReturn(mockVC);

        LEARCredentialMachine learCredentialMachine = mock(LEARCredentialMachine.class);
        when(objectMapper.convertValue(mockVC, LEARCredentialMachine.class)).thenReturn(learCredentialMachine);
        when(learCredentialMachine.type()).thenReturn(List.of(LEARCredentialType.LEAR_CREDENTIAL_MACHINE.getValue()));

        when(clientAssertionValidationService.validateClientAssertionJWTClaims(anyString(), any())).thenReturn(true);
        when(vpService.validateVerifiablePresentation(anyString())).thenReturn(true);

        OAuth2ClientCredentialsAuthenticationToken result =
                (OAuth2ClientCredentialsAuthenticationToken) customTokenRequestConverter.convert(mockRequest);

        assertNotNull(result);
        assertEquals("client-id", result.getAdditionalParameters().get(OAuth2ParameterNames.CLIENT_ID));
        assertEquals(mockVC, result.getAdditionalParameters().get("vc"));

        verify(clientAssertionValidationService, times(1)).validateClientAssertionJWTClaims(anyString(), any());
        verify(vpService, times(1)).validateVerifiablePresentation(anyString());
    }

    @Test
    void convert_clientCredentialsGrant_shouldReturnIllegalArgumentException_Invalid_JWT_claims_from_assertion() {
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        Authentication clientPrincipal = mock(Authentication.class);
        SecurityContextHolder.getContext().setAuthentication(clientPrincipal);

        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.add(OAuth2ParameterNames.GRANT_TYPE, "client_credentials");
        parameters.add(OAuth2ParameterNames.CLIENT_ID, "client-id");
        parameters.add(OAuth2ParameterNames.CLIENT_ASSERTION, "client-assertion");

        when(mockRequest.getParameterMap()).thenReturn(convertToMap(parameters));

        SignedJWT signedJWT = mock(SignedJWT.class);
        when(jwtService.parseJWT("client-assertion")).thenReturn(signedJWT);

        String vpToken = "vp-token";
        when(jwtService.getClaimFromPayload(any(), eq("vp_token"))).thenReturn(vpToken);

        JsonNode mockVC = mock(JsonNode.class);
        when(vpService.getCredentialFromTheVerifiablePresentationAsJsonNode(anyString())).thenReturn(mockVC);

        LEARCredentialMachine learCredentialMachine = mock(LEARCredentialMachine.class);
        when(objectMapper.convertValue(mockVC, LEARCredentialMachine.class)).thenReturn(learCredentialMachine);
        when(learCredentialMachine.type()).thenReturn(List.of(LEARCredentialType.LEAR_CREDENTIAL_MACHINE.getValue()));

        when(clientAssertionValidationService.validateClientAssertionJWTClaims(anyString(), any())).thenReturn(false);

        assertThrows(IllegalArgumentException.class, () ->
                customTokenRequestConverter.convert(mockRequest));
    }

    @Test
    void convert_clientCredentialsGrant_shouldReturnIllegalArgumentException_Invalid_VP_Token() {
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        Authentication clientPrincipal = mock(Authentication.class);
        SecurityContextHolder.getContext().setAuthentication(clientPrincipal);

        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.add(OAuth2ParameterNames.GRANT_TYPE, "client_credentials");
        parameters.add(OAuth2ParameterNames.CLIENT_ID, "client-id");
        parameters.add(OAuth2ParameterNames.CLIENT_ASSERTION, "client-assertion");

        when(mockRequest.getParameterMap()).thenReturn(convertToMap(parameters));

        SignedJWT signedJWT = mock(SignedJWT.class);
        when(jwtService.parseJWT("client-assertion")).thenReturn(signedJWT);

        String vpToken = "vp-token";
        when(jwtService.getClaimFromPayload(any(), eq("vp_token"))).thenReturn(vpToken);

        JsonNode mockVC = mock(JsonNode.class);
        when(vpService.getCredentialFromTheVerifiablePresentationAsJsonNode(anyString())).thenReturn(mockVC);

        LEARCredentialMachine learCredentialMachine = mock(LEARCredentialMachine.class);
        when(objectMapper.convertValue(mockVC, LEARCredentialMachine.class)).thenReturn(learCredentialMachine);
        when(learCredentialMachine.type()).thenReturn(List.of(LEARCredentialType.LEAR_CREDENTIAL_MACHINE.getValue()));

        when(clientAssertionValidationService.validateClientAssertionJWTClaims(anyString(), any())).thenReturn(true);
        when(vpService.validateVerifiablePresentation(anyString())).thenReturn(false);

        assertThrows(IllegalArgumentException.class, () ->
                customTokenRequestConverter.convert(mockRequest));
    }

    @Test
    void handleM2MGrant_invalidCredentialType_shouldThrowInvalidCredentialTypeException() {
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        Authentication clientPrincipal = mock(Authentication.class);
        SecurityContextHolder.getContext().setAuthentication(clientPrincipal);

        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.add(OAuth2ParameterNames.GRANT_TYPE, "client_credentials");
        parameters.add(OAuth2ParameterNames.CLIENT_ID, "client-id");
        parameters.add(OAuth2ParameterNames.CLIENT_ASSERTION, "client-assertion");

        when(mockRequest.getParameterMap()).thenReturn(convertToMap(parameters));

        SignedJWT signedJWT = mock(SignedJWT.class);
        when(jwtService.parseJWT("client-assertion")).thenReturn(signedJWT);

        String vpToken = "vp-token";
        when(jwtService.getClaimFromPayload(any(), eq("vp_token"))).thenReturn(vpToken);

        // Mock the behavior of getCredentialFromTheVerifiablePresentationAsJsonNode with the correct vpToken
        JsonNode mockVC = mock(JsonNode.class);
        when(vpService.getCredentialFromTheVerifiablePresentationAsJsonNode(vpToken)).thenReturn(mockVC);

        LEARCredentialMachine learCredentialMachine = mock(LEARCredentialMachine.class);
        when(objectMapper.convertValue(mockVC, LEARCredentialMachine.class)).thenReturn(learCredentialMachine);

        // Simulate an invalid LEARCredentialType
        when(learCredentialMachine.type()).thenReturn(List.of("InvalidType"));

        // Verify the exception is thrown
        assertThrows(InvalidCredentialTypeException.class, () ->
                customTokenRequestConverter.convert(mockRequest));
    }


    @Test
    void convert_unsupportedGrantType_shouldThrowUnsupportedGrantTypeException() {
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);

        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.add(OAuth2ParameterNames.GRANT_TYPE, "invalid_grant_type");

        when(mockRequest.getParameterMap()).thenReturn(convertToMap(parameters));

        assertThrows(UnsupportedGrantTypeException.class, () ->
                customTokenRequestConverter.convert(mockRequest));
    }


    // Helper method to convert MultiValueMap to a regular Map for the request mock
    private Map<String, String[]> convertToMap(MultiValueMap<String, String> multiValueMap) {
        Map<String, String[]> map = new HashMap<>();
        multiValueMap.forEach((key, valueList) -> map.put(key, valueList.toArray(new String[0])));
        return map;
    }

}
