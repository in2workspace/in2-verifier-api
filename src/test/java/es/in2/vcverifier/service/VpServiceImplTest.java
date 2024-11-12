package es.in2.vcverifier.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.shaded.gson.internal.LinkedTreeMap;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.exception.JsonConversionException;
import es.in2.vcverifier.model.credentials.Mandator;
import es.in2.vcverifier.model.credentials.employee.CredentialSubjectLCEmployee;
import es.in2.vcverifier.model.credentials.employee.LEARCredentialEmployee;
import es.in2.vcverifier.model.credentials.employee.MandateLCEmployee;
import es.in2.vcverifier.model.credentials.employee.MandateeLCEmployee;
import es.in2.vcverifier.model.enums.KeyType;
import es.in2.vcverifier.model.issuer.IssuerCredentialsCapabilities;
import es.in2.vcverifier.model.issuer.TimeRange;
import es.in2.vcverifier.service.impl.VpServiceImpl;
import es.in2.vcverifier.util.CertificateUtils;
import org.assertj.core.api.Assertions;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class VpServiceImplTest {

    @Mock
    private JWTService jwtService;

    @Mock
    private TrustFrameworkService trustFrameworkService;

    @Mock
    private DIDService didService;

    @Mock
    private ObjectMapper objectMapper;

    @InjectMocks
    private VpServiceImpl vpServiceImpl;

    @Test
    void getCredentialFromTheVerifiablePresentation_success(){
        String verifiablePresentation = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQ6a2V5OnpEbmFlblF6WEthVE5SNlYyaWZyY0VFU042VFR1WWpweWFmUGh0c1pZU3Y0VlJia3IiLCJuYmYiOjE3MTc0MzgwMDMsImlzcyI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sImhvbGRlciI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsImlkIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIiwidHlwZSI6WyJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIl0sInZlcmlmaWFibGVDcmVkZW50aWFsIjpbImV5SmhiR2NpT2lKSVV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUp6ZFdJaU9pSXhNak0wTlRZM09Ea3dJaXdpYm1GdFpTSTZJa3B2YUc0Z1JHOWxJaXdpYVdGMElqb3hOVEUyTWpNNU1ESXlmUS5TZmxLeHdSSlNNZUtLRjJRVDRmd3BNZUpmMzZQT2s2eUpWX2FkUXNzdzVjIl19LCJleHAiOjE3MjAwMzAwMDMsImlhdCI6MTcxNzQzODAwMywianRpIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIn0._tIB_9fsQjZmJV2cgGDWtYXmps9fbLbMDtu8wZhIwC9u6I7RAaR4NK5WrnRC1TIVbQa06ZeneELxc_ktTkdhfA";

        Payload payload = mock(Payload.class);
        when(jwtService.getPayloadFromSignedJWT(any(SignedJWT.class))).thenReturn(payload);

        Object mockVC = new Object();
        when(jwtService.getVCFromPayload(payload)).thenReturn(mockVC);
        Object result = vpServiceImpl.getCredentialFromTheVerifiablePresentation(verifiablePresentation);

        Assertions.assertThat(mockVC)
                .isNotNull()
                .isEqualTo(result);
        ;
        verify(jwtService, times(1)).getPayloadFromSignedJWT(any(SignedJWT.class));
        verify(jwtService, times(1)).getVCFromPayload(any(Payload.class));
    }

    @Test
    void getCredentialFromTheVerifiablePresentationAsJsonNode_with_VC_JSONObject_success() throws JsonProcessingException {
        String verifiablePresentation = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQ6a2V5OnpEbmFlblF6WEthVE5SNlYyaWZyY0VFU042VFR1WWpweWFmUGh0c1pZU3Y0VlJia3IiLCJuYmYiOjE3MTc0MzgwMDMsImlzcyI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sImhvbGRlciI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsImlkIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIiwidHlwZSI6WyJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIl0sInZlcmlmaWFibGVDcmVkZW50aWFsIjpbImV5SmhiR2NpT2lKSVV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUp6ZFdJaU9pSXhNak0wTlRZM09Ea3dJaXdpYm1GdFpTSTZJa3B2YUc0Z1JHOWxJaXdpYVdGMElqb3hOVEUyTWpNNU1ESXlmUS5TZmxLeHdSSlNNZUtLRjJRVDRmd3BNZUpmMzZQT2s2eUpWX2FkUXNzdzVjIl19LCJleHAiOjE3MjAwMzAwMDMsImlhdCI6MTcxNzQzODAwMywianRpIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIn0._tIB_9fsQjZmJV2cgGDWtYXmps9fbLbMDtu8wZhIwC9u6I7RAaR4NK5WrnRC1TIVbQa06ZeneELxc_ktTkdhfA";

        Payload payload = mock(Payload.class);
        when(jwtService.getPayloadFromSignedJWT(any(SignedJWT.class))).thenReturn(payload);

        JSONObject mockVC = new JSONObject();
        when(jwtService.getVCFromPayload(payload)).thenReturn(mockVC);

        JsonNode jsonNode = mock(JsonNode.class);
        when(objectMapper.readTree(mockVC.toString())).thenReturn(jsonNode);

        Object result = vpServiceImpl.getCredentialFromTheVerifiablePresentationAsJsonNode(verifiablePresentation);

        Assertions.assertThat(mockVC).isNotNull();
        Assertions.assertThat(jsonNode).isEqualTo(result);

        verify(jwtService, times(1)).getPayloadFromSignedJWT(any(SignedJWT.class));
        verify(jwtService, times(1)).getVCFromPayload(any(Payload.class));
        verify(objectMapper, times(1)).readTree(any(String.class));
    }

    @Test
    void getCredentialFromTheVerifiablePresentationAsJsonNode_with_VC_Map_success() {
        String verifiablePresentation = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQ6a2V5OnpEbmFlblF6WEthVE5SNlYyaWZyY0VFU042VFR1WWpweWFmUGh0c1pZU3Y0VlJia3IiLCJuYmYiOjE3MTc0MzgwMDMsImlzcyI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sImhvbGRlciI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsImlkIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIiwidHlwZSI6WyJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIl0sInZlcmlmaWFibGVDcmVkZW50aWFsIjpbImV5SmhiR2NpT2lKSVV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUp6ZFdJaU9pSXhNak0wTlRZM09Ea3dJaXdpYm1GdFpTSTZJa3B2YUc0Z1JHOWxJaXdpYVdGMElqb3hOVEUyTWpNNU1ESXlmUS5TZmxLeHdSSlNNZUtLRjJRVDRmd3BNZUpmMzZQT2s2eUpWX2FkUXNzdzVjIl19LCJleHAiOjE3MjAwMzAwMDMsImlhdCI6MTcxNzQzODAwMywianRpIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIn0._tIB_9fsQjZmJV2cgGDWtYXmps9fbLbMDtu8wZhIwC9u6I7RAaR4NK5WrnRC1TIVbQa06ZeneELxc_ktTkdhfA";

        Payload payload = mock(Payload.class);
        when(jwtService.getPayloadFromSignedJWT(any(SignedJWT.class))).thenReturn(payload);

        Map<String, String> mockVC = new HashMap<>();
        when(jwtService.getVCFromPayload(payload)).thenReturn(mockVC);

        JsonNode jsonNode = mock(JsonNode.class);
        when(objectMapper.convertValue(mockVC, JsonNode.class)).thenReturn(jsonNode);

        Object result = vpServiceImpl.getCredentialFromTheVerifiablePresentationAsJsonNode(verifiablePresentation);

        Assertions.assertThat(mockVC).isNotNull();
        Assertions.assertThat(jsonNode).isEqualTo(result);

        verify(jwtService, times(1)).getPayloadFromSignedJWT(any(SignedJWT.class));
        verify(jwtService, times(1)).getVCFromPayload(any(Payload.class));
        verify(objectMapper, times(1)).convertValue(mockVC,JsonNode.class);
    }

    @Test
    void getCredentialFromTheVerifiablePresentationAsJsonNode_with_VC_unsupported_instance_throw_JsonConversionException(){
        String verifiablePresentation = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQ6a2V5OnpEbmFlblF6WEthVE5SNlYyaWZyY0VFU042VFR1WWpweWFmUGh0c1pZU3Y0VlJia3IiLCJuYmYiOjE3MTc0MzgwMDMsImlzcyI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sImhvbGRlciI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsImlkIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIiwidHlwZSI6WyJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIl0sInZlcmlmaWFibGVDcmVkZW50aWFsIjpbImV5SmhiR2NpT2lKSVV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUp6ZFdJaU9pSXhNak0wTlRZM09Ea3dJaXdpYm1GdFpTSTZJa3B2YUc0Z1JHOWxJaXdpYVdGMElqb3hOVEUyTWpNNU1ESXlmUS5TZmxLeHdSSlNNZUtLRjJRVDRmd3BNZUpmMzZQT2s2eUpWX2FkUXNzdzVjIl19LCJleHAiOjE3MjAwMzAwMDMsImlhdCI6MTcxNzQzODAwMywianRpIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIn0._tIB_9fsQjZmJV2cgGDWtYXmps9fbLbMDtu8wZhIwC9u6I7RAaR4NK5WrnRC1TIVbQa06ZeneELxc_ktTkdhfA";

        Payload payload = mock(Payload.class);
        when(jwtService.getPayloadFromSignedJWT(any(SignedJWT.class))).thenReturn(payload);

        Object mockVC = new Object();
        when(jwtService.getVCFromPayload(payload)).thenReturn(mockVC);

        JsonConversionException thrown = assertThrows(JsonConversionException.class, () -> vpServiceImpl.getCredentialFromTheVerifiablePresentationAsJsonNode(verifiablePresentation));

        Assertions.assertThat(thrown.getMessage()).isEqualTo("Error durante la conversión a JsonNode.");

        verify(jwtService, times(1)).getPayloadFromSignedJWT(any(SignedJWT.class));

    }

    @Test
    void getCredentialFromTheVerifiablePresentationAsJsonNode_with_VC_Map_throw_JsonConversionException_when_mapping(){
        String verifiablePresentation = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQ6a2V5OnpEbmFlblF6WEthVE5SNlYyaWZyY0VFU042VFR1WWpweWFmUGh0c1pZU3Y0VlJia3IiLCJuYmYiOjE3MTc0MzgwMDMsImlzcyI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sImhvbGRlciI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsImlkIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIiwidHlwZSI6WyJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIl0sInZlcmlmaWFibGVDcmVkZW50aWFsIjpbImV5SmhiR2NpT2lKSVV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUp6ZFdJaU9pSXhNak0wTlRZM09Ea3dJaXdpYm1GdFpTSTZJa3B2YUc0Z1JHOWxJaXdpYVdGMElqb3hOVEUyTWpNNU1ESXlmUS5TZmxLeHdSSlNNZUtLRjJRVDRmd3BNZUpmMzZQT2s2eUpWX2FkUXNzdzVjIl19LCJleHAiOjE3MjAwMzAwMDMsImlhdCI6MTcxNzQzODAwMywianRpIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIn0._tIB_9fsQjZmJV2cgGDWtYXmps9fbLbMDtu8wZhIwC9u6I7RAaR4NK5WrnRC1TIVbQa06ZeneELxc_ktTkdhfA";

        Payload payload = mock(Payload.class);
        when(jwtService.getPayloadFromSignedJWT(any(SignedJWT.class))).thenReturn(payload);

        Map<String, Object> mockVC = new HashMap<>();

        when(jwtService.getVCFromPayload(payload)).thenReturn(mockVC);

        when(objectMapper.convertValue(mockVC, JsonNode.class)).thenThrow(new IllegalArgumentException(new JsonConversionException("Error durante la conversión a JsonNode.")));


        JsonConversionException thrown = assertThrows(JsonConversionException.class, () -> vpServiceImpl.getCredentialFromTheVerifiablePresentationAsJsonNode(verifiablePresentation));

        Assertions.assertThat(thrown.getMessage()).isEqualTo("Error durante la conversión a JsonNode.");

    }

    @Test
    void getCredentialFromTheVerifiablePresentationAsJsonNode_with_VC_JSONObject_throw_JsonConversionException_when_mapping() throws JsonProcessingException {
        String verifiablePresentation = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQ6a2V5OnpEbmFlblF6WEthVE5SNlYyaWZyY0VFU042VFR1WWpweWFmUGh0c1pZU3Y0VlJia3IiLCJuYmYiOjE3MTc0MzgwMDMsImlzcyI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sImhvbGRlciI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsImlkIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIiwidHlwZSI6WyJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIl0sInZlcmlmaWFibGVDcmVkZW50aWFsIjpbImV5SmhiR2NpT2lKSVV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUp6ZFdJaU9pSXhNak0wTlRZM09Ea3dJaXdpYm1GdFpTSTZJa3B2YUc0Z1JHOWxJaXdpYVdGMElqb3hOVEUyTWpNNU1ESXlmUS5TZmxLeHdSSlNNZUtLRjJRVDRmd3BNZUpmMzZQT2s2eUpWX2FkUXNzdzVjIl19LCJleHAiOjE3MjAwMzAwMDMsImlhdCI6MTcxNzQzODAwMywianRpIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIn0._tIB_9fsQjZmJV2cgGDWtYXmps9fbLbMDtu8wZhIwC9u6I7RAaR4NK5WrnRC1TIVbQa06ZeneELxc_ktTkdhfA";

        Payload payload = mock(Payload.class);
        when(jwtService.getPayloadFromSignedJWT(any(SignedJWT.class))).thenReturn(payload);

        JSONObject mockVC = new JSONObject();

        when(jwtService.getVCFromPayload(payload)).thenReturn(mockVC);

        when(objectMapper.readTree(mockVC.toString())).thenThrow(new JsonConversionException("Error durante la conversión a JsonNode."));


        JsonConversionException thrown = assertThrows(JsonConversionException.class, () -> vpServiceImpl.getCredentialFromTheVerifiablePresentationAsJsonNode(verifiablePresentation));

        Assertions.assertThat(thrown.getMessage()).isEqualTo("Error durante la conversión a JsonNode.");

    }

    @Test
    void validateVerifiablePresentation_vp_claim_with_verifiableCredential_claim_string_but_not_jwt_format_throws_JWTParsingException_and_return_false() {
        String vpClaimWithVcNotJwtFormat = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQ6a2V5OnpEbmFlblF6WEthVE5SNlYyaWZyY0VFU042VFR1WWpweWFmUGh0c1pZU3Y0VlJia3IiLCJuYmYiOjE3MTc0MzgwMDMsImlzcyI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sImhvbGRlciI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsImlkIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIiwidHlwZSI6WyJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIl0sInZlcmlmaWFibGVDcmVkZW50aWFsIjpbImludmFsaWQtand0Il19LCJleHAiOjE3MjAwMzAwMDMsImlhdCI6MTcxNzQzODAwMywianRpIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIn0.MHfKhZCCmXUlAwdgC_cT5bWJyINKeMjVDiXx3dCBKydSPdzX3QO2kiESeoO1tmzolA-7KRtJj7R-b6HfNE4xbA";

        boolean result = vpServiceImpl.validateVerifiablePresentation(vpClaimWithVcNotJwtFormat);

        Assertions.assertThat(result).isFalse();
    }

    @Test
    void validateVerifiablePresentation_vp_claim_with_verifiableCredential_claim_no_string_format_throws_CredentialException_and_return_false() {
        String vpClaimWithVcNotStringFormat = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQ6a2V5OnpEbmFlblF6WEthVE5SNlYyaWZyY0VFU042VFR1WWpweWFmUGh0c1pZU3Y0VlJia3IiLCJuYmYiOjE3MTc0MzgwMDMsImlzcyI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sImhvbGRlciI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsImlkIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIiwidHlwZSI6WyJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIl0sInZlcmlmaWFibGVDcmVkZW50aWFsIjpbMV19LCJleHAiOjE3MjAwMzAwMDMsImlhdCI6MTcxNzQzODAwMywianRpIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIn0.K-bG85t--QMmOumsZsNbk7Vm62AUsl8kgDxwH3G9---Eb7xfX0NkVuq1r2iTh-H2uRNcpmnao03Y8fbrnYVqFA";

        boolean result = vpServiceImpl.validateVerifiablePresentation(vpClaimWithVcNotStringFormat);

        Assertions.assertThat(result).isFalse();
    }

    @Test
    void validateVerifiablePresentation_vp_claim_with_verifiableCredential_claim_is_not_found_throws_CredentialException_and_return_false() {
        String vpClaimWithVcArrayEmpty = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQ6a2V5OnpEbmFlblF6WEthVE5SNlYyaWZyY0VFU042VFR1WWpweWFmUGh0c1pZU3Y0VlJia3IiLCJuYmYiOjE3MTc0MzgwMDMsImlzcyI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sImhvbGRlciI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsImlkIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIiwidHlwZSI6WyJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIl0sInZlcmlmaWFibGVDcmVkZW50aWFsIjpbXX0sImV4cCI6MTcyMDAzMDAwMywiaWF0IjoxNzE3NDM4MDAzLCJqdGkiOiI0MWFjYWRhMy02N2I0LTQ5NGUtYTZlMy1lMDk2NjQ0OWYyNWQifQ.kR4ob7mBGb246EpUYpMRKaESEqGc7yZaNnyoZpkxbMrF_bgC9VLRmMagsHP4DXfl7f8XyBUKFyUcda2PUPs-bA";

        boolean result = vpServiceImpl.validateVerifiablePresentation(vpClaimWithVcArrayEmpty);

        Assertions.assertThat(result).isFalse();
    }

    @Test
    void validateVerifiablePresentation_vp_claim_with_verifiableCredential_claim_is_not_an_array_throws_CredentialException_and_return_false() {
        String vpClaimWithVcNotArrayFormat = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQ6a2V5OnpEbmFlblF6WEthVE5SNlYyaWZyY0VFU042VFR1WWpweWFmUGh0c1pZU3Y0VlJia3IiLCJuYmYiOjE3MTc0MzgwMDMsImlzcyI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sImhvbGRlciI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsImlkIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIiwidHlwZSI6WyJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIl0sInZlcmlmaWFibGVDcmVkZW50aWFsIjoibm90LWFycmF5LWZvcm1hdCJ9LCJleHAiOjE3MjAwMzAwMDMsImlhdCI6MTcxNzQzODAwMywianRpIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIn0.0Jpm4g5IUBnZRH5Zf1FSs0nSJmdD9dQncchlFJoqT_tDU733rXLT7UbD0f4KIfwPPZn_APKNt-h5ziTQjgXJiw";

        boolean result = vpServiceImpl.validateVerifiablePresentation(vpClaimWithVcNotArrayFormat);

        Assertions.assertThat(result).isFalse();
    }

    @Test
    void validateVerifiablePresentation_vp_claim_without_verifiableCredential_claim_inside_throws_JWTClaimMissingException_and_return_false() {
        String vpClaimNotValidObject = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJ2cCI6e319.hLaehswoW9QiU_FmLGCDZIPOvnNOvn2HsOCs9lKhHUE";

        boolean result = vpServiceImpl.validateVerifiablePresentation(vpClaimNotValidObject);

        Assertions.assertThat(result).isFalse();
    }

    @Test
    void validateVerifiablePresentation_vp_claim_not_valid_object_throws_JWTClaimMissingException_and_return_false() {
        String vpClaimNotValidObject = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJ2cCI6ImludmFsaWRWcEZvcm1hdCJ9.5-6R9OxqX7lXEEqVL_12Bf0UODXnkPtrt_ntoD2IrPQ";

        boolean result = vpServiceImpl.validateVerifiablePresentation(vpClaimNotValidObject);

        Assertions.assertThat(result).isFalse();
    }

    @Test
    void validateVerifiablePresentation_invalidVP_throws_JWTClaimMissingException_and_return_false() {
        String jwtWithoutVpClaim = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

        boolean result = vpServiceImpl.validateVerifiablePresentation(jwtWithoutVpClaim);

        Assertions.assertThat(result).isFalse();
    }

    @Test
    void validateVerifiablePresentation_invalidVP_throws_JWTParsingException_and_return_false() {
        String invalidVP = "invalidVPJWT";

        boolean result = vpServiceImpl.validateVerifiablePresentation(invalidVP);

        Assertions.assertThat(result).isFalse();
    }

    @Test
    void validateVerifiablePresentation_success() throws Exception {
        // Given
        String verifiablePresentation = "valid.vp.jwt";

        // Step 1: Parse the VP JWT
        SignedJWT vpSignedJWT = mock(SignedJWT.class);
        try (MockedStatic<SignedJWT> mockedSignedJWT = mockStatic(SignedJWT.class);
             MockedStatic<CertificateUtils> mockedCertificateUtils = mockStatic(CertificateUtils.class)) {

            mockedSignedJWT.when(() -> SignedJWT.parse(verifiablePresentation)).thenReturn(vpSignedJWT);

            // Set up the VP claims
            JWTClaimsSet vpClaimsSet = mock(JWTClaimsSet.class);
            when(vpSignedJWT.getJWTClaimsSet()).thenReturn(vpClaimsSet);

            // Mock the "vp" claim in the VP
            Map<String, Object> vcClaimMap = new HashMap<>();
            String vcJwt = "valid.vc.jwt";
            vcClaimMap.put("verifiableCredential", List.of(vcJwt));
            when(vpClaimsSet.getClaim("vp")).thenReturn(vcClaimMap);

            // Step 2: Parse the VC JWT
            SignedJWT jwtCredential = mock(SignedJWT.class);
            mockedSignedJWT.when(() -> SignedJWT.parse(vcJwt)).thenReturn(jwtCredential);

            Payload payload = mock(Payload.class);
            when(jwtService.getPayloadFromSignedJWT(jwtCredential)).thenReturn(payload);

            // Step 3: Validate the credential id is not in the revoked list
            // Create a vcFromPayload Map with the "id" field
            LinkedTreeMap<String, Object> vcFromPayload = new LinkedTreeMap<>();
            vcFromPayload.put("id", "credential-id-123");
            when(jwtService.getVCFromPayload(payload)).thenReturn(vcFromPayload);

            // Mock trustFrameworkService.getRevokedCredentialIds to return an empty list
            when(trustFrameworkService.getRevokedCredentialIds()).thenReturn(Collections.emptyList());

            // Step 4: Validate the issuer
            String credentialIssuerDid = "did:elsi:issuer123";
            when(jwtService.getClaimFromPayload(payload, "iss")).thenReturn(credentialIssuerDid);

            // Step 5: Extract and validate credential types
            vcFromPayload.put("type", List.of("LEARCredentialEmployee"));

            // Step 6: Retrieve the list of issuer capabilities
            List<IssuerCredentialsCapabilities> issuerCapabilitiesList = List.of(
                    IssuerCredentialsCapabilities.builder()
                            .validFor(new TimeRange(Instant.now().toString(), Instant.now().plusSeconds(3600).toString()))
                            .credentialsType("LEARCredentialEmployee")
                            .claims(null)
                            .build()
            );
            when(trustFrameworkService.getTrustedIssuerListData(credentialIssuerDid)).thenReturn(issuerCapabilitiesList);

            // Step 7: Verify the signature and the organizationId of the credential signature
            Map<String, Object> vcHeader = new HashMap<>();
            vcHeader.put("x5c", List.of("base64Cert"));
            JWSHeader header = mock(JWSHeader.class);
            when(jwtCredential.getHeader()).thenReturn(header);
            when(header.toJSONObject()).thenReturn(vcHeader);

            // Mock CertificateUtils.extractAndVerifyCertificate
            PublicKey certPubKey = generateRSAPublicKey();
            mockedCertificateUtils.when(() -> CertificateUtils.extractAndVerifyCertificate(eq(vcHeader), anyString())).thenReturn(certPubKey);

            when(jwtCredential.serialize()).thenReturn(vcJwt);
            // Mock jwtService.verifyJWTSignature for the Verifiable Credential
            doNothing().when(jwtService).verifyJWTSignature(any(), eq(certPubKey), eq(KeyType.RSA));

            // Step 8: Mock the mapping to LEARCredentialEmployee
            LEARCredentialEmployee learCredentialEmployee = mock(LEARCredentialEmployee.class);
            CredentialSubjectLCEmployee credentialSubject = mock(CredentialSubjectLCEmployee.class);
            MandateLCEmployee mandate = mock(MandateLCEmployee.class);
            Mandator mandator = mock(Mandator.class);
            MandateeLCEmployee mandatee = mock(MandateeLCEmployee.class);

            when(learCredentialEmployee.credentialSubject()).thenReturn(credentialSubject);
            when(credentialSubject.mandate()).thenReturn(mandate);
            when(mandate.mandator()).thenReturn(mandator);
            when(mandator.organizationIdentifier()).thenReturn("org123");
            when(mandate.mandatee()).thenReturn(mandatee);
            when(mandatee.id()).thenReturn("did:example:mandatee123");

            when(objectMapper.convertValue(vcFromPayload, LEARCredentialEmployee.class)).thenReturn(learCredentialEmployee);

            // Step 9: Validate the mandator with trusted issuer service
            when(trustFrameworkService.getTrustedIssuerListData("did:elsi:org123")).thenReturn(issuerCapabilitiesList);

            // Step 11: Get the holder's public key
            PublicKey holderPublicKey = generateECPublicKey();
            when(didService.getPublicKeyFromDid("did:example:mandatee123")).thenReturn(holderPublicKey);

            // Mock jwtService.verifyJWTSignature for the Verifiable Presentation
            doNothing().when(jwtService).verifyJWTSignature(verifiablePresentation, holderPublicKey, KeyType.EC);

            // When
            boolean result = vpServiceImpl.validateVerifiablePresentation(verifiablePresentation);

            // Then
            assertTrue(result);

            // Verify interactions
            verify(jwtService).verifyJWTSignature(verifiablePresentation, holderPublicKey, KeyType.EC);
            verify(jwtService).verifyJWTSignature(vcJwt, certPubKey, KeyType.RSA);
        }
    }

    private RSAPublicKey generateRSAPublicKey() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return (RSAPublicKey) keyPairGenerator.generateKeyPair().getPublic();
    }
    private ECPublicKey generateECPublicKey() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));
        return (ECPublicKey) keyPairGenerator.generateKeyPair().getPublic();
    }

}
