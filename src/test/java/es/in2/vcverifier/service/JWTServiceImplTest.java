package es.in2.vcverifier.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.crypto.CryptoComponent;
import es.in2.vcverifier.exception.JWTClaimMissingException;
import es.in2.vcverifier.exception.JWTCreationException;
import es.in2.vcverifier.exception.JWTParsingException;
import es.in2.vcverifier.exception.JWTVerificationException;
import es.in2.vcverifier.model.enums.KeyType;
import es.in2.vcverifier.service.impl.JWTServiceImpl;
import org.json.JSONObject;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
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
    void generateJWT_succes() throws Exception {

        String privateKeyJson = "{\"kty\":\"EC\",\"d\":\"MDtaBGOjN0SY0NtX2hFvv4uJNLrUGUWHvquqNZHwi5s\",\"use\":\"sig\",\"crv\":\"P-256\",\"kid\":\"75bb28ac9f4247248c73348f890e050c\",\"x\":\"E9pfJi7I29gtdofnJJBvC_DK3KH1eTialAMOoX6CfZw\",\"y\":\"hDfdnEyabkB-9Hf1PFYaYomSdYVwJ0NSM5CzxhOUIr0\",\"alg\":\"ES256\"}";
        String did = "did:example:1234";

        // Simulating the JWTClaimsSet payload
        JWTClaimsSet payload = new JWTClaimsSet.Builder()
                .issuer(did)
                .audience(did)
                .build();


        JsonNode mockJsonNode = mock(JsonNode.class);
        when(objectMapper.readTree(anyString())).thenReturn(mockJsonNode);

        Map<String, Object> claimsMap  = new HashMap<>();
        claimsMap.put("someKey", "someValue");

        when(objectMapper.convertValue(any(JsonNode.class), any(TypeReference.class))).thenReturn(claimsMap);

        ECKey ecJWK = new ECKey.Builder(Curve.P_256, (ECPublicKey) getPublicKeyFromJson(privateKeyJson))
                .privateKey(getPrivateKeyFromJson(privateKeyJson))
                .keyID(did)
                .build();

        when(cryptoComponent.getECKey()).thenReturn(ecJWK);

        String result = jwtService.generateJWT(payload.toString());

        assertNotNull(result);
        verify(cryptoComponent,times(2)).getECKey();

    }

    @Test
    void generateJWT_invalidPayload_throwsJWTCreationException() throws Exception {
        String invalidPayload = "invalid-payload";
        String privateKeyJson = "{\"kty\":\"EC\",\"d\":\"MDtaBGOjN0SY0NtX2hFvv4uJNLrUGUWHvquqNZHwi5s\",\"use\":\"sig\",\"crv\":\"P-256\",\"kid\":\"75bb28ac9f4247248c73348f890e050c\",\"x\":\"E9pfJi7I29gtdofnJJBvC_DK3KH1eTialAMOoX6CfZw\",\"y\":\"hDfdnEyabkB-9Hf1PFYaYomSdYVwJ0NSM5CzxhOUIr0\",\"alg\":\"ES256\"}";
        String did = "did:example:1234";

        ECKey ecJWK = new ECKey.Builder(Curve.P_256, (ECPublicKey) getPublicKeyFromJson(privateKeyJson))
                .privateKey(getPrivateKeyFromJson(privateKeyJson))
                .keyID(did)
                .build();

        when(cryptoComponent.getECKey()).thenReturn(ecJWK);
        when(objectMapper.readTree(anyString())).thenThrow(JsonProcessingException.class);

        assertThrows(JWTCreationException.class, () -> jwtService.generateJWT(invalidPayload));

    }



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

    @Test
    void verifyJWTSignature_EC_Success() throws Exception {
        // Prepare data
        String privateKeyJson = "{\"kty\":\"EC\",\"d\":\"WyM7H0IaIeDDoJ4WKjohkwkmrBmQ3rYrFNBrGsSzKtM\",\"use\":\"sig\",\"crv\":\"P-256\",\"kid\":\"75bb28ac9f4247248c73348f890e050c\",\"x\":\"RqEzut-nsajrrT4_UphUuaiseuSCdO5SqUd6LkaYW9c\",\"y\":\"vJ-OQ9EUBXmLOJW1zCuT24NzUEbm0WjUsF2wdedpUY8\",\"alg\":\"ES256\"}";
        String jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQ6a2V5OnpEbmFlblF6WEthVE5SNlYyaWZyY0VFU042VFR1WWpweWFmUGh0c1pZU3Y0VlJia3IiLCJuYmYiOjE3MTc0MzgwMDMsImlzcyI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sImhvbGRlciI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsImlkIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIiwidHlwZSI6WyJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIl0sInZlcmlmaWFibGVDcmVkZW50aWFsIjpbImV5SmhiR2NpT2lKSVV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUp6ZFdJaU9pSXhNak0wTlRZM09Ea3dJaXdpYm1GdFpTSTZJa3B2YUc0Z1JHOWxJaXdpYVdGMElqb3hOVEUyTWpNNU1ESXlmUS5TZmxLeHdSSlNNZUtLRjJRVDRmd3BNZUpmMzZQT2s2eUpWX2FkUXNzdzVjIl19LCJleHAiOjE3MjAwMzAwMDMsImlhdCI6MTcxNzQzODAwMywianRpIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIn0.BMv-_OkIT0H1KHeWm2FYZnUwc8mJfZGTA9B6HwYhdeX5THcLchQ2P6xDbIXH6WpBOlDAcwSy3BUv2ZqyCa6inA\n";
        KeyType keyType = KeyType.EC; // Specify EC as key type

        SignedJWT signedJWT = mock(SignedJWT.class);

        try (var mockStaticSignedJWT = mockStatic(SignedJWT.class)) {
            mockStaticSignedJWT.when(() -> SignedJWT.parse(jwt))
                    .thenReturn(signedJWT);
        }

        // Execute the method to verify the JWT signature
        ECPublicKey ecPublicKey = (ECPublicKey) getPublicKeyFromJson(privateKeyJson);

        jwtService.verifyJWTSignature(jwt, ecPublicKey, keyType);

    }

    @Test
    void verifyJWTSignature_EC_with_invalid_publicKey_throws_IllegalArgumentException_and_then_JWTVerificationException() throws Exception {
        // Prepare data
        String jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQ6a2V5OnpEbmFlblF6WEthVE5SNlYyaWZyY0VFU042VFR1WWpweWFmUGh0c1pZU3Y0VlJia3IiLCJuYmYiOjE3MTc0MzgwMDMsImlzcyI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sImhvbGRlciI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsImlkIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIiwidHlwZSI6WyJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIl0sInZlcmlmaWFibGVDcmVkZW50aWFsIjpbImV5SmhiR2NpT2lKSVV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUp6ZFdJaU9pSXhNak0wTlRZM09Ea3dJaXdpYm1GdFpTSTZJa3B2YUc0Z1JHOWxJaXdpYVdGMElqb3hOVEUyTWpNNU1ESXlmUS5TZmxLeHdSSlNNZUtLRjJRVDRmd3BNZUpmMzZQT2s2eUpWX2FkUXNzdzVjIl19LCJleHAiOjE3MjAwMzAwMDMsImlhdCI6MTcxNzQzODAwMywianRpIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIn0.BMv-_OkIT0H1KHeWm2FYZnUwc8mJfZGTA9B6HwYhdeX5THcLchQ2P6xDbIXH6WpBOlDAcwSy3BUv2ZqyCa6inA\n";
        KeyType keyType = KeyType.EC; // Specify EC as key type
        RSAPublicKey publicKeyInvalid = mock(RSAPublicKey.class);

        SignedJWT signedJWT = mock(SignedJWT.class);

        try (var mockStaticSignedJWT = mockStatic(SignedJWT.class)) {
            mockStaticSignedJWT.when(() -> SignedJWT.parse(jwt))
                    .thenReturn(signedJWT);
        }

        assertThrows(JWTVerificationException.class, () -> jwtService.verifyJWTSignature(jwt, publicKeyInvalid, keyType));

    }

    //TODO not working

//    @Test
//    void verifyJWTSignature_RSA_Success() throws Exception {
//
//
//        // Prepare data
//        String privateKeyJson = "{\"kty\":\"EC\",\"d\":\"WyM7H0IaIeDDoJ4WKjohkwkmrBmQ3rYrFNBrGsSzKtM\",\"use\":\"sig\",\"crv\":\"P-256\",\"kid\":\"75bb28ac9f4247248c73348f890e050c\",\"x\":\"RqEzut-nsajrrT4_UphUuaiseuSCdO5SqUd6LkaYW9c\",\"y\":\"vJ-OQ9EUBXmLOJW1zCuT24NzUEbm0WjUsF2wdedpUY8\",\"alg\":\"ES256\"}";
//        String jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjE4MDNhNTgyMWY0MTA0OGRiMDY0MGQ0OGIyNTI0YzU5In0.e30.HGKZ8u1Sd2pQ_rDHMNYkOSFwfQ-0rZs6nE5wBMKRrgaN3K_kHluogJ_u42fOJ47AtU8TkbbjcQ7XTmUZyojsAl4d_eLsE-pmT6KHhqw4p3I8lisSXfGQkspHpJ38-gwkqle9ZmtvrnksWHN9ufnEdBPI4lc2O1y017_V0GM0vJ6zFVbCFK7tSh1KPt5zQ6yvApgLlcSczCAW40zUagKJjuPfayIRPkjelJW4VoeI4BtqfmonUPie13dloKcIAkzImMDQRjOIBJXdl_ipXfzsyvcSF8Lfj-vBVCXyCxBj5Y1_4l8fFee8Pg4ZMKGyYpW8n7VFUnfiex6CUFw19lEsNf4iIPuk0gNN98xRNMCbYJU15NFunPvEOmhKm8b6nDWLnj4HN9_FHahZ2iQRhCd53UiwaVrYWOCEzv4xFfzcrECl5VdcAOE4QK9OaktSPCj_901V6DJryMRXjHoSbY6PALOCK_X0D4eGCWXLmEgzYYqNt2oq_qgr4QDEndOeeud6";
//        KeyType keyType = KeyType.RSA; // Specify EC as key type
//        RSAPublicKey publicKey = mock(RSAPublicKey.class);
//
//        SignedJWT signedJWT = mock(SignedJWT.class);
//
//        try (var mockStaticSignedJWT = mockStatic(SignedJWT.class)) {
//            mockStaticSignedJWT.when(() -> SignedJWT.parse(jwt))
//                    .thenReturn(signedJWT);
//        }
//
//        jwtService.verifyJWTSignature(jwt, publicKey, keyType);
//
//    }

    @Test
    void verifyJWTSignature_RSA_with_invalid_publicKey_throws_IllegalArgumentException_and_then_JWTVerificationException() throws Exception {
        // Prepare data
        String jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQ6a2V5OnpEbmFlblF6WEthVE5SNlYyaWZyY0VFU042VFR1WWpweWFmUGh0c1pZU3Y0VlJia3IiLCJuYmYiOjE3MTc0MzgwMDMsImlzcyI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sImhvbGRlciI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsImlkIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIiwidHlwZSI6WyJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIl0sInZlcmlmaWFibGVDcmVkZW50aWFsIjpbImV5SmhiR2NpT2lKSVV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUp6ZFdJaU9pSXhNak0wTlRZM09Ea3dJaXdpYm1GdFpTSTZJa3B2YUc0Z1JHOWxJaXdpYVdGMElqb3hOVEUyTWpNNU1ESXlmUS5TZmxLeHdSSlNNZUtLRjJRVDRmd3BNZUpmMzZQT2s2eUpWX2FkUXNzdzVjIl19LCJleHAiOjE3MjAwMzAwMDMsImlhdCI6MTcxNzQzODAwMywianRpIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIn0.BMv-_OkIT0H1KHeWm2FYZnUwc8mJfZGTA9B6HwYhdeX5THcLchQ2P6xDbIXH6WpBOlDAcwSy3BUv2ZqyCa6inA\n";
        KeyType keyType = KeyType.RSA; // Specify EC as key type
        ECPublicKey publicKeyInvalid = mock(ECPublicKey.class);

        SignedJWT signedJWT = mock(SignedJWT.class);

        try (var mockStaticSignedJWT = mockStatic(SignedJWT.class)) {
            mockStaticSignedJWT.when(() -> SignedJWT.parse(jwt))
                    .thenReturn(signedJWT);
        }

        assertThrows(JWTVerificationException.class, () -> jwtService.verifyJWTSignature(jwt, publicKeyInvalid, keyType));

    }

    @Test
    void verifyJWTSignature_with_invalid_publicKey_throws_JWTVerificationException() throws Exception {
        // Prepare data
        String privateKeyJson = "{\"kty\":\"EC\",\"d\":\"WyM7H0IaIeDDoJ4WKjohkwkmrBmQ3rYrFNBrGsSzKtM\",\"use\":\"sig\",\"crv\":\"P-256\",\"kid\":\"75bb28ac9f4247248c73348f890e050c\",\"x\":\"invalid\",\"y\":\"invalid\",\"alg\":\"ES256\"}";
        String jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQ6a2V5OnpEbmFlblF6WEthVE5SNlYyaWZyY0VFU042VFR1WWpweWFmUGh0c1pZU3Y0VlJia3IiLCJuYmYiOjE3MTc0MzgwMDMsImlzcyI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sImhvbGRlciI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsImlkIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIiwidHlwZSI6WyJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIl0sInZlcmlmaWFibGVDcmVkZW50aWFsIjpbImV5SmhiR2NpT2lKSVV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUp6ZFdJaU9pSXhNak0wTlRZM09Ea3dJaXdpYm1GdFpTSTZJa3B2YUc0Z1JHOWxJaXdpYVdGMElqb3hOVEUyTWpNNU1ESXlmUS5TZmxLeHdSSlNNZUtLRjJRVDRmd3BNZUpmMzZQT2s2eUpWX2FkUXNzdzVjIl19LCJleHAiOjE3MjAwMzAwMDMsImlhdCI6MTcxNzQzODAwMywianRpIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIn0.BMv-_OkIT0H1KHeWm2FYZnUwc8mJfZGTA9B6HwYhdeX5THcLchQ2P6xDbIXH6WpBOlDAcwSy3BUv2ZqyCa6inA\n";
        KeyType keyType = KeyType.EC; // Specify EC as key type

        SignedJWT signedJWT = mock(SignedJWT.class);

        try (var mockStaticSignedJWT = mockStatic(SignedJWT.class)) {
            mockStaticSignedJWT.when(() -> SignedJWT.parse(jwt))
                    .thenReturn(signedJWT);
        }

        // Execute the method to verify the JWT signature
        ECPublicKey ecPublicKey = (ECPublicKey) getPublicKeyFromJson(privateKeyJson);

        assertThrows(JWTVerificationException.class, () -> jwtService.verifyJWTSignature(jwt, ecPublicKey, keyType));

    }

    private PrivateKey getPrivateKeyFromJson(String json) throws Exception {
        JSONObject jsonKey = new JSONObject(json);

        String privateKeyEncoded = jsonKey.getString("d");

        // Decode base64url
        byte[] privateKeyBytes = Base64URL.from(privateKeyEncoded).decode();

        // Create an EC parameter specification
        ECGenParameterSpec ecSpec = new ECGenParameterSpec(Curve.P_256.getStdName());
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC");
        keyPairGen.initialize(ecSpec, new SecureRandom());
        KeyPair keyPair = keyPairGen.generateKeyPair();
        ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();

        // Build the EC private key from the bytes
        ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(new BigInteger(1, privateKeyBytes), publicKey.getParams());
        KeyFactory keyFactory = KeyFactory.getInstance("EC");

        return keyFactory.generatePrivate(privateKeySpec);
    }

    public static PublicKey getPublicKeyFromJson(String json) throws Exception {
        // Parse the JSON
        JSONObject jsonKey = new JSONObject(json);

        // Extract the x and y coordinates for the public key
        String xEncoded = jsonKey.getString("x");
        String yEncoded = jsonKey.getString("y");

        // Decode the base64url values
        byte[] xBytes = Base64URL.from(xEncoded).decode();
        byte[] yBytes = Base64URL.from(yEncoded).decode();

        // Create the ECPoint (public key point) from x and y coordinates
        ECPoint ecPoint = new ECPoint(new BigInteger(1, xBytes), new BigInteger(1, yBytes));

        // Specify the curve
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1"); // P-256 curve
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC");
        keyPairGen.initialize(ecSpec, new SecureRandom());

        // Generate a dummy key pair to obtain the EC parameters
        KeyPair keyPair = keyPairGen.generateKeyPair();
        ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
        ECParameterSpec ecParams = publicKey.getParams();

        // Build the public key spec
        ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(ecPoint, ecParams);

        // Create the public key
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return keyFactory.generatePublic(pubKeySpec);
    }

}
