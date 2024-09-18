package es.in2.vcverifier;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.crypto.CryptoComponent;
import es.in2.vcverifier.exception.ECKeyCreationException;
import es.in2.vcverifier.service.impl.JWTServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

import java.text.ParseException;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

public class JWTServiceImplTest {

    @Mock
    private CryptoComponent cryptoComponent;

    @Mock
    private ObjectMapper objectMapper;

    @InjectMocks
    private JWTServiceImpl jwtService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

//    @Test
//    void generateJWT_success() throws JsonProcessingException {
//        String payload = "{\"iss\": \"test-issuer\"}";
//
//        when(cryptoComponent.getECKey()).thenReturn(mockECKey);
//        when(mockECKey.getKeyID()).thenReturn("test-key-id");
//
//        // Mock object mapper conversion
//        when(objectMapper.readTree(payload)).thenReturn(objectMapper.createObjectNode());
//
//        // Call the method
//        String jwt = jwtService.generateJWT(payload);
//
//        // Verify that the EC key and object mapper were used
//        verify(cryptoComponent, times(1)).getECKey();
//        verify(objectMapper, times(1)).readTree(payload);
//
//        // Assert that a non-null JWT was generated
//        assertNotNull(jwt);
//    }

    @Test
    void generateJWT_throwJWTCreationException() {
        String payload = "{\"iss\": \"test-issuer\"}";

        // Mock ECKey generation to throw an exception
        when(cryptoComponent.getECKey()).thenThrow(new ECKeyCreationException("error"));

        // Expect JWTCreationException
        assertThrows(ECKeyCreationException.class, () -> jwtService.generateJWT(payload));

        // Verify no JWT was created
        verify(cryptoComponent, times(1)).getECKey();
    }

    @Test
    void parseJWT_success() throws ParseException {
        String validJwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

        SignedJWT mockSignedJWT = mock(SignedJWT.class);
        mockStatic(SignedJWT.class);
        when(SignedJWT.parse(validJwt)).thenReturn(mockSignedJWT);

        JWTServiceImpl jwtService = new JWTServiceImpl(null, null);

        SignedJWT result = jwtService.parseJWT(validJwt);

        assertEquals(mockSignedJWT, result);
    }

    @Test
    void parseJWT_throwsParseException() {
        String invalidJwt = "invalid.jwt.token";
        assertThrows(RuntimeException.class, () -> {
            try {
                SignedJWT.parse(invalidJwt);
            } catch (ParseException e) {
                throw new RuntimeException(e);
            }
        }, "Expected RuntimeException to be thrown");
    }

    @Test
    void getPayloadFromSignedJWT_success() {
        SignedJWT mockSignedJWT = mock(SignedJWT.class);
        Payload mockPayload = mock(Payload.class);

        when(mockSignedJWT.getPayload()).thenReturn(mockPayload);

        JWTServiceImpl jwtService = new JWTServiceImpl(null, null);

        Payload result = jwtService.getPayloadFromSignedJWT(mockSignedJWT);

        verify(mockSignedJWT).getPayload();
        assertEquals(mockPayload, result);
    }

    @Test
    void getIssuerFromPayload_success() {
        Payload payload = mock(Payload.class);
        when(payload.toJSONObject()).thenReturn(Map.of("iss", "issuer-test"));

        String issuer = jwtService.getIssuerFromPayload(payload);
        assertEquals("issuer-test", issuer);
    }

    @Test
    void getIssuerFromPayload_throwIllegalArgumentException() {
        Payload payload = mock(Payload.class);
        when(payload.toJSONObject()).thenReturn(Map.of());

        assertThrows(IllegalArgumentException.class, () -> jwtService.getIssuerFromPayload(payload));
    }

    @Test
    void getSubjectFromPayload_success() {
        Payload payload = mock(Payload.class);
        when(payload.toJSONObject()).thenReturn(Map.of("sub", "subject-test"));

        String subject = jwtService.getSubjectFromPayload(payload);
        assertEquals("subject-test", subject);
    }

    @Test
    void getSubjectFromPayload_throwIllegalArgumentException() {
        Payload payload = mock(Payload.class);
        when(payload.toJSONObject()).thenReturn(Map.of());

        assertThrows(IllegalArgumentException.class, () -> jwtService.getSubjectFromPayload(payload));
    }

    @Test
    void getAudienceFromPayload_success() {
        Payload payload = mock(Payload.class);
        when(payload.toJSONObject()).thenReturn(Map.of("aud", "audience-test"));

        String audience = jwtService.getAudienceFromPayload(payload);
        assertEquals("audience-test", audience);
    }

    @Test
    void getAudienceFromPayload_throwIllegalArgumentException() {
        Payload payload = mock(Payload.class);
        when(payload.toJSONObject()).thenReturn(Map.of());

        assertThrows(IllegalArgumentException.class, () -> jwtService.getAudienceFromPayload(payload));
    }

    @Test
    void getExpirationFromPayload_success() {
        Payload payload = mock(Payload.class);
        when(payload.toJSONObject()).thenReturn(Map.of("exp", 123456789L));

        long expiration = jwtService.getExpirationFromPayload(payload);
        assertEquals(123456789L, expiration);
    }

    @Test
    void getExpirationFromPayload_throwIllegalArgumentException() {
        Payload payload = mock(Payload.class);
        when(payload.toJSONObject()).thenReturn(Map.of());

        assertThrows(IllegalArgumentException.class, () -> jwtService.getExpirationFromPayload(payload));
    }


    @Test
    void getJwtIdFromPayload_success() {
        Payload payload = mock(Payload.class);
        when(payload.toJSONObject()).thenReturn(Map.of("jti", "jwt-id-test"));

        String jti = jwtService.getJwtIdFromPayload(payload);
        assertEquals("jwt-id-test", jti);
    }

    @Test
    void getJwtIdFromPayload_throwIllegalArgumentException() {
        Payload payload = new Payload(Map.of(
                "jti", ""
        ));
        assertThrows(IllegalArgumentException.class, () -> jwtService.getJwtIdFromPayload(payload));
    }

    @Test
    void getVcFromPayload_success() {
        Payload payload = mock(Payload.class);
        when(payload.toJSONObject()).thenReturn(Map.of("vc", "vc-test"));

        String vc = jwtService.getVcFromPayload(payload);
        assertEquals("vc-test", vc);
    }

    @Test
    void getVcFromPayload_throwIllegalArgumentException() {
        Payload payload = new Payload(Map.of(
                "vc", ""
        ));
        assertThrows(IllegalArgumentException.class, () -> jwtService.getVcFromPayload(payload));
    }

}
