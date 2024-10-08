package es.in2.vcverifier.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.crypto.CryptoComponent;
import es.in2.vcverifier.exception.JWTClaimMissingException;
import es.in2.vcverifier.exception.JWTCreationException;
import es.in2.vcverifier.exception.JWTParsingException;
import es.in2.vcverifier.service.impl.JWTServiceImpl;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JWTServiceImplTest {

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private CryptoComponent cryptoComponent;

    @InjectMocks
    private JWTServiceImpl jwtService;

    @Test
    void generateJWT_throws_JWTCreationException() throws JsonProcessingException {
        String payload = "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"iat\":1516239022}";

        ECKey ecKey = mock(ECKey.class);
        when(ecKey.getKeyID()).thenReturn("testKeyID");
        when(ecKey.getCurve()).thenReturn(Curve.P_256);
        when(cryptoComponent.getECKey()).thenReturn(ecKey);

        JsonNode mockJsonNode = mock(JsonNode.class);
        when(objectMapper.readTree(payload)).thenReturn(mockJsonNode);

        Map<String, Object> claimsMap  = new HashMap<>();
        claimsMap .put("sub", "1234567890");
        claimsMap .put("name", "John Doe");
        claimsMap .put("iat", 1516239022);
        when(objectMapper.convertValue(any(JsonNode.class), any(TypeReference.class))).thenReturn(claimsMap);

        assertThrows(JWTCreationException.class, () -> jwtService.generateJWT(payload));
    }

    @Test
    void parseJWT_validToken_shouldReturnSignedJWT() {
        String jwtToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

        SignedJWT result = jwtService.parseJWT(jwtToken);

        assertNotNull(result);
    }

    @Test
    void parseJWT_invalidToken_shouldThrowJWTParsingException() {
        String invalidToken = "invalid.jwt.token";

        try (var mockStaticSignedJWT = mockStatic(SignedJWT.class)) {
            mockStaticSignedJWT.when(() -> SignedJWT.parse(invalidToken))
                    .thenThrow(new ParseException("Invalid token", 0));

            JWTParsingException exception = assertThrows(JWTParsingException.class, () -> jwtService.parseJWT(invalidToken));

            Assertions.assertEquals("Error al parsear el JWTs", exception.getMessage());
        }
    }

    @Test
    void getPayloadFromSignedJWT_validSignedJWT_shouldReturnPayload() {
        SignedJWT signedJWTMock = mock(SignedJWT.class);
        Payload payloadMock = mock(Payload.class);
        when(signedJWTMock.getPayload()).thenReturn(payloadMock);

        Payload result = jwtService.getPayloadFromSignedJWT(signedJWTMock);

        assertNotNull(result);
        Assertions.assertEquals(payloadMock, result);
    }

    @Test
    void getClaimFromPayload_validClaim_shouldReturnClaimValue() {
        Payload payloadMock = mock(Payload.class);
        String claimName = "sub";
        String claimValue = "subject";

        Map<String, Object> claimsMap = new HashMap<>();
        claimsMap.put(claimName, claimValue);

        when(payloadMock.toJSONObject()).thenReturn(claimsMap);

        String result = jwtService.getClaimFromPayload(payloadMock, claimName);

        assertNotNull(result);
        Assertions.assertEquals(claimValue, result);
    }

    @Test
    void getClaimFromPayload_missingClaim_shouldThrowJWTClaimMissingException() {
        Payload payloadMock = mock(Payload.class);
        String claimName = "sub";

        when(payloadMock.toJSONObject()).thenReturn(new HashMap<>());

        JWTClaimMissingException exception = assertThrows(JWTClaimMissingException.class, () -> jwtService.getClaimFromPayload(payloadMock, claimName));

        Assertions.assertEquals(String.format("The '%s' claim is missing or empty in the JWT payload.", claimName), exception.getMessage());
    }

    @Test
    void getClaimFromPayload_emptyClaim_shouldThrowJWTClaimMissingException() {
        Payload payloadMock = mock(Payload.class);
        String claimName = "sub";
        String emptyClaimValue = "";

        Map<String, Object> claimsMap = new HashMap<>();
        claimsMap.put(claimName, emptyClaimValue);

        when(payloadMock.toJSONObject()).thenReturn(claimsMap);

        JWTClaimMissingException exception = assertThrows(JWTClaimMissingException.class, () -> jwtService.getClaimFromPayload(payloadMock, claimName));

        Assertions.assertEquals(String.format("The '%s' claim is missing or empty in the JWT payload.", claimName), exception.getMessage());
    }

    @Test
    void getExpirationFromPayload_validExp_shouldReturnExpiration() throws ParseException {
        Payload payload = mock(Payload.class);
        when(payload.toJSONObject()).thenReturn(JSONObjectUtils.parse("{\"exp\": 1716239022}"));

        long expiration = jwtService.getExpirationFromPayload(payload);

        assertEquals(1716239022, expiration);
    }

    @Test
    void getExpirationFromPayload_invalidExp_shouldThrowJWTClaimMissingException() throws ParseException {
        Payload payload = mock(Payload.class);
        when(payload.toJSONObject()).thenReturn(JSONObjectUtils.parse("{\"exp\": -1000}"));

        assertThrows(JWTClaimMissingException.class, () -> jwtService.getExpirationFromPayload(payload));
    }

    @Test
    void getVCFromPayload_validVC_shouldReturnVC() throws ParseException {
        Payload payload = mock(Payload.class);
        when(payload.toJSONObject()).thenReturn(JSONObjectUtils.parse("{\"vc\": \"verifiableCredential\"}"));

        Object vc = jwtService.getVCFromPayload(payload);

        assertEquals("verifiableCredential", vc);
    }


}
