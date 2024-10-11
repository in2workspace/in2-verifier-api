package es.in2.vcverifier.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.shaded.gson.internal.LinkedTreeMap;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.exception.CredentialMappingException;
import es.in2.vcverifier.exception.JWTParsingException;
import es.in2.vcverifier.exception.JsonConversionException;
import es.in2.vcverifier.exception.UnsupportedDIDTypeException;
import es.in2.vcverifier.model.credentials.employee.CredentialSubjectLCEmployee;
import es.in2.vcverifier.model.credentials.employee.LEARCredentialEmployee;
import es.in2.vcverifier.model.credentials.employee.MandateLCEmployee;
import es.in2.vcverifier.model.credentials.employee.MandateeLCEmployee;
import es.in2.vcverifier.model.credentials.machine.CredentialSubjectLCMachine;
import es.in2.vcverifier.model.credentials.machine.LEARCredentialMachine;
import es.in2.vcverifier.model.credentials.machine.MandateLCMachine;
import es.in2.vcverifier.model.credentials.machine.MandateeLCMachine;
import es.in2.vcverifier.model.enums.KeyType;
import es.in2.vcverifier.model.issuer.IssuerCredentialsCapabilities;
import es.in2.vcverifier.model.issuer.TimeRange;
import es.in2.vcverifier.service.impl.VpServiceImpl;
import org.assertj.core.api.Assertions;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.PublicKey;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class VpServiceImplTest {

    @Mock
    private JWTService jwtService;

    @Mock
    private TrustedIssuerListService trustedIssuerListService;

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

        Assertions.assertThat(mockVC).isNotNull();
        Assertions.assertThat(mockVC).isEqualTo(result);

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
    void getCredentialFromTheVerifiablePresentationAsJsonNode_with_VC_Map_success() throws JsonProcessingException {
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
    void validateVerifiablePresentation_vp_claim_with_verifiableCredential_claim_with_LEARCredentialMachine_return_true() {
        String verifiablePresentation = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQ6a2V5OnpEbmFlblF6WEthVE5SNlYyaWZyY0VFU042VFR1WWpweWFmUGh0c1pZU3Y0VlJia3IiLCJuYmYiOjE3MTc0MzgwMDMsImlzcyI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sImhvbGRlciI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsImlkIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIiwidHlwZSI6WyJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIl0sInZlcmlmaWFibGVDcmVkZW50aWFsIjpbImV5SmhiR2NpT2lKSVV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUp6ZFdJaU9pSXhNak0wTlRZM09Ea3dJaXdpYm1GdFpTSTZJa3B2YUc0Z1JHOWxJaXdpYVdGMElqb3hOVEUyTWpNNU1ESXlmUS5TZmxLeHdSSlNNZUtLRjJRVDRmd3BNZUpmMzZQT2s2eUpWX2FkUXNzdzVjIl19LCJleHAiOjE3MjAwMzAwMDMsImlhdCI6MTcxNzQzODAwMywianRpIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIn0._tIB_9fsQjZmJV2cgGDWtYXmps9fbLbMDtu8wZhIwC9u6I7RAaR4NK5WrnRC1TIVbQa06ZeneELxc_ktTkdhfA";

        Payload payload = mock(Payload.class);
        when(jwtService.getPayloadFromSignedJWT(any(SignedJWT.class))).thenReturn(payload);

        String issuerDid = "did:example:issuer";
        when(jwtService.getClaimFromPayload(eq(payload), eq("iss"))).thenReturn(issuerDid);

        LinkedTreeMap<String, Object> vcMap = new LinkedTreeMap<>();
        vcMap.put("type", Arrays.asList("VerifiableCredential","LEARCredentialMachine"));

        when(jwtService.getVCFromPayload(eq(payload))).thenReturn(vcMap);

        IssuerCredentialsCapabilities issuerCredentialsCapabilities = IssuerCredentialsCapabilities.builder().credentialsType("VerifiableCredential").build();
        when(trustedIssuerListService.getTrustedIssuerListData(issuerDid)).thenReturn(List.of(issuerCredentialsCapabilities));

        when(objectMapper.convertValue(vcMap, LEARCredentialMachine.class)).thenReturn(
                LEARCredentialMachine.builder()
                        .credentialSubject(CredentialSubjectLCMachine
                                .builder().mandate(MandateLCMachine
                                        .builder().mandatee(MandateeLCMachine
                                                .builder().id("mandateeId")
                                                .build())
                                        .build())
                                .build())
                        .build());

        PublicKey holderPublicKey = mock(PublicKey.class);
        when(didService.getPublicKeyFromDid(anyString())).thenReturn(holderPublicKey);

        doNothing().when(jwtService).verifyJWTSignature(verifiablePresentation, holderPublicKey, KeyType.EC);

        boolean result = vpServiceImpl.validateVerifiablePresentation(verifiablePresentation);

        Assertions.assertThat(result).isTrue();
    }

    @Test
    void validateVerifiablePresentation_vp_claim_with_verifiableCredential_claim_with_LEARCredentialEmployee_return_true() {
        String verifiablePresentation = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQ6a2V5OnpEbmFlblF6WEthVE5SNlYyaWZyY0VFU042VFR1WWpweWFmUGh0c1pZU3Y0VlJia3IiLCJuYmYiOjE3MTc0MzgwMDMsImlzcyI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sImhvbGRlciI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsImlkIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIiwidHlwZSI6WyJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIl0sInZlcmlmaWFibGVDcmVkZW50aWFsIjpbImV5SmhiR2NpT2lKSVV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUp6ZFdJaU9pSXhNak0wTlRZM09Ea3dJaXdpYm1GdFpTSTZJa3B2YUc0Z1JHOWxJaXdpYVdGMElqb3hOVEUyTWpNNU1ESXlmUS5TZmxLeHdSSlNNZUtLRjJRVDRmd3BNZUpmMzZQT2s2eUpWX2FkUXNzdzVjIl19LCJleHAiOjE3MjAwMzAwMDMsImlhdCI6MTcxNzQzODAwMywianRpIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIn0._tIB_9fsQjZmJV2cgGDWtYXmps9fbLbMDtu8wZhIwC9u6I7RAaR4NK5WrnRC1TIVbQa06ZeneELxc_ktTkdhfA";

        Payload payload = mock(Payload.class);
        when(jwtService.getPayloadFromSignedJWT(any(SignedJWT.class))).thenReturn(payload);

        String issuerDid = "did:example:issuer";
        when(jwtService.getClaimFromPayload(eq(payload), eq("iss"))).thenReturn(issuerDid);

        LinkedTreeMap<String, Object> vcMap = new LinkedTreeMap<>();
        vcMap.put("type", Arrays.asList("VerifiableCredential","LEARCredentialEmployee"));

        when(jwtService.getVCFromPayload(eq(payload))).thenReturn(vcMap);

        IssuerCredentialsCapabilities issuerCredentialsCapabilities = IssuerCredentialsCapabilities.builder().credentialsType("VerifiableCredential").build();
        when(trustedIssuerListService.getTrustedIssuerListData(issuerDid)).thenReturn(List.of(issuerCredentialsCapabilities));

        when(objectMapper.convertValue(vcMap, LEARCredentialEmployee.class)).thenReturn(
                LEARCredentialEmployee.builder()
                        .credentialSubject(CredentialSubjectLCEmployee
                                .builder().mandate(MandateLCEmployee
                                        .builder().mandatee(MandateeLCEmployee
                                                .builder().id("mandateeId")
                                                .build())
                                        .build())
                                .build())
                        .build());

        PublicKey holderPublicKey = mock(PublicKey.class);
        when(didService.getPublicKeyFromDid(anyString())).thenReturn(holderPublicKey);

        doNothing().when(jwtService).verifyJWTSignature(verifiablePresentation, holderPublicKey, KeyType.EC);

        boolean result = vpServiceImpl.validateVerifiablePresentation(verifiablePresentation);

        Assertions.assertThat(result).isTrue();
    }

    @Test
    void validateVerifiablePresentation_vp_claim_with_verifiableCredential_claim_with_LEARCredentialMachine_throws_IllegalArgumentException_and_CredentialMappingException_when_map_and_return_false() {
        String vpClaimWithVcJwtFormat = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQ6a2V5OnpEbmFlblF6WEthVE5SNlYyaWZyY0VFU042VFR1WWpweWFmUGh0c1pZU3Y0VlJia3IiLCJuYmYiOjE3MTc0MzgwMDMsImlzcyI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sImhvbGRlciI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsImlkIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIiwidHlwZSI6WyJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIl0sInZlcmlmaWFibGVDcmVkZW50aWFsIjpbImV5SmhiR2NpT2lKSVV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUp6ZFdJaU9pSXhNak0wTlRZM09Ea3dJaXdpYm1GdFpTSTZJa3B2YUc0Z1JHOWxJaXdpYVdGMElqb3hOVEUyTWpNNU1ESXlmUS5TZmxLeHdSSlNNZUtLRjJRVDRmd3BNZUpmMzZQT2s2eUpWX2FkUXNzdzVjIl19LCJleHAiOjE3MjAwMzAwMDMsImlhdCI6MTcxNzQzODAwMywianRpIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIn0._tIB_9fsQjZmJV2cgGDWtYXmps9fbLbMDtu8wZhIwC9u6I7RAaR4NK5WrnRC1TIVbQa06ZeneELxc_ktTkdhfA";

        Payload payload = mock(Payload.class);
        when(jwtService.getPayloadFromSignedJWT(any(SignedJWT.class))).thenReturn(payload);

        String issuerDid = "did:example:issuer";
        when(jwtService.getClaimFromPayload(eq(payload), eq("iss"))).thenReturn(issuerDid);

        LinkedTreeMap<String, Object> vcMap = new LinkedTreeMap<>();
        vcMap.put("type", Arrays.asList("VerifiableCredential","LEARCredentialMachine"));
        when(jwtService.getVCFromPayload(eq(payload))).thenReturn(vcMap);

        IssuerCredentialsCapabilities issuerCredentialsCapabilities = IssuerCredentialsCapabilities.builder().credentialsType("VerifiableCredential").build();
        when(trustedIssuerListService.getTrustedIssuerListData(issuerDid)).thenReturn(List.of(issuerCredentialsCapabilities));

        when(objectMapper.convertValue(vcMap, LEARCredentialMachine.class))
                .thenThrow(new IllegalArgumentException(new CredentialMappingException("Error converting VC to LEARCredentialMachine")));

        boolean result = vpServiceImpl.validateVerifiablePresentation(vpClaimWithVcJwtFormat);

        Assertions.assertThat(result).isFalse();
    }

    @Test
    void validateVerifiablePresentation_vp_claim_with_verifiableCredential_claim_with_LEARCredentialEmployee_throws_IllegalArgumentException_and_CredentialMappingException_when_map_and_return_false() {
        String vpClaimWithVcJwtFormat = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQ6a2V5OnpEbmFlblF6WEthVE5SNlYyaWZyY0VFU042VFR1WWpweWFmUGh0c1pZU3Y0VlJia3IiLCJuYmYiOjE3MTc0MzgwMDMsImlzcyI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sImhvbGRlciI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsImlkIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIiwidHlwZSI6WyJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIl0sInZlcmlmaWFibGVDcmVkZW50aWFsIjpbImV5SmhiR2NpT2lKSVV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUp6ZFdJaU9pSXhNak0wTlRZM09Ea3dJaXdpYm1GdFpTSTZJa3B2YUc0Z1JHOWxJaXdpYVdGMElqb3hOVEUyTWpNNU1ESXlmUS5TZmxLeHdSSlNNZUtLRjJRVDRmd3BNZUpmMzZQT2s2eUpWX2FkUXNzdzVjIl19LCJleHAiOjE3MjAwMzAwMDMsImlhdCI6MTcxNzQzODAwMywianRpIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIn0._tIB_9fsQjZmJV2cgGDWtYXmps9fbLbMDtu8wZhIwC9u6I7RAaR4NK5WrnRC1TIVbQa06ZeneELxc_ktTkdhfA";

        Payload payload = mock(Payload.class);
        when(jwtService.getPayloadFromSignedJWT(any(SignedJWT.class))).thenReturn(payload);

        String issuerDid = "did:example:issuer";
        when(jwtService.getClaimFromPayload(eq(payload), eq("iss"))).thenReturn(issuerDid);

        LinkedTreeMap<String, Object> vcMap = new LinkedTreeMap<>();
        vcMap.put("type", Arrays.asList("VerifiableCredential","LEARCredentialEmployee"));
        when(jwtService.getVCFromPayload(eq(payload))).thenReturn(vcMap);

        IssuerCredentialsCapabilities issuerCredentialsCapabilities = IssuerCredentialsCapabilities.builder().credentialsType("VerifiableCredential").build();
        when(trustedIssuerListService.getTrustedIssuerListData(issuerDid)).thenReturn(List.of(issuerCredentialsCapabilities));

        when(objectMapper.convertValue(vcMap, LEARCredentialEmployee.class))
                .thenThrow(new IllegalArgumentException(new CredentialMappingException("Error converting VC to LEARCredentialEmployee")));

        boolean result = vpServiceImpl.validateVerifiablePresentation(vpClaimWithVcJwtFormat);

        Assertions.assertThat(result).isFalse();
    }

    @Test
    void validateVerifiablePresentation_vp_claim_with_verifiableCredential_claim_with_Invalid_Credential_Type_beacause_is_not_LEARCredentialEmployee_or_LEARCredentialMachine_and_return_false() {
        String vpClaimWithVcJwtFormat = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQ6a2V5OnpEbmFlblF6WEthVE5SNlYyaWZyY0VFU042VFR1WWpweWFmUGh0c1pZU3Y0VlJia3IiLCJuYmYiOjE3MTc0MzgwMDMsImlzcyI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sImhvbGRlciI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsImlkIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIiwidHlwZSI6WyJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIl0sInZlcmlmaWFibGVDcmVkZW50aWFsIjpbImV5SmhiR2NpT2lKSVV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUp6ZFdJaU9pSXhNak0wTlRZM09Ea3dJaXdpYm1GdFpTSTZJa3B2YUc0Z1JHOWxJaXdpYVdGMElqb3hOVEUyTWpNNU1ESXlmUS5TZmxLeHdSSlNNZUtLRjJRVDRmd3BNZUpmMzZQT2s2eUpWX2FkUXNzdzVjIl19LCJleHAiOjE3MjAwMzAwMDMsImlhdCI6MTcxNzQzODAwMywianRpIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIn0._tIB_9fsQjZmJV2cgGDWtYXmps9fbLbMDtu8wZhIwC9u6I7RAaR4NK5WrnRC1TIVbQa06ZeneELxc_ktTkdhfA";

        Payload payload = mock(Payload.class);
        when(jwtService.getPayloadFromSignedJWT(any(SignedJWT.class))).thenReturn(payload);

        String issuerDid = "did:example:issuer";
        when(jwtService.getClaimFromPayload(eq(payload), eq("iss"))).thenReturn(issuerDid);

        LinkedTreeMap<String, Object> vcMap = new LinkedTreeMap<>();
        vcMap.put("type", Arrays.asList("VerifiableCredential","UnsupportedCredentialType"));
        when(jwtService.getVCFromPayload(eq(payload))).thenReturn(vcMap);

        IssuerCredentialsCapabilities issuerCredentialsCapabilities = IssuerCredentialsCapabilities.builder().credentialsType("VerifiableCredential").build();
        when(trustedIssuerListService.getTrustedIssuerListData(issuerDid)).thenReturn(List.of(issuerCredentialsCapabilities));

        boolean result = vpServiceImpl.validateVerifiablePresentation(vpClaimWithVcJwtFormat);

        Assertions.assertThat(result).isFalse();
    }

    @Test
    void validateVerifiablePresentation_vp_claim_with_verifiableCredential_claim_with_Unsupported_credential_types_by_the_issuer_throws_InvalidCredentialTypeException_and_return_false() {
        String vpClaimWithVcJwtFormat = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQ6a2V5OnpEbmFlblF6WEthVE5SNlYyaWZyY0VFU042VFR1WWpweWFmUGh0c1pZU3Y0VlJia3IiLCJuYmYiOjE3MTc0MzgwMDMsImlzcyI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sImhvbGRlciI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsImlkIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIiwidHlwZSI6WyJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIl0sInZlcmlmaWFibGVDcmVkZW50aWFsIjpbImV5SmhiR2NpT2lKSVV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUp6ZFdJaU9pSXhNak0wTlRZM09Ea3dJaXdpYm1GdFpTSTZJa3B2YUc0Z1JHOWxJaXdpYVdGMElqb3hOVEUyTWpNNU1ESXlmUS5TZmxLeHdSSlNNZUtLRjJRVDRmd3BNZUpmMzZQT2s2eUpWX2FkUXNzdzVjIl19LCJleHAiOjE3MjAwMzAwMDMsImlhdCI6MTcxNzQzODAwMywianRpIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIn0._tIB_9fsQjZmJV2cgGDWtYXmps9fbLbMDtu8wZhIwC9u6I7RAaR4NK5WrnRC1TIVbQa06ZeneELxc_ktTkdhfA";

        Payload payload = mock(Payload.class);
        when(jwtService.getPayloadFromSignedJWT(any(SignedJWT.class))).thenReturn(payload);

        String issuerDid = "did:example:issuer";
        when(jwtService.getClaimFromPayload(eq(payload), eq("iss"))).thenReturn(issuerDid);

        LinkedTreeMap<String, Object> vcMap = new LinkedTreeMap<>();
        vcMap.put("type", Arrays.asList("VerifiableCredential","LEARCredentialEmployee"));
        when(jwtService.getVCFromPayload(eq(payload))).thenReturn(vcMap);

        IssuerCredentialsCapabilities issuerCredentialsCapabilities = IssuerCredentialsCapabilities.builder().credentialsType("UnsupportedCredentialType").build();
        when(trustedIssuerListService.getTrustedIssuerListData(issuerDid)).thenReturn(List.of(issuerCredentialsCapabilities));

        boolean result = vpServiceImpl.validateVerifiablePresentation(vpClaimWithVcJwtFormat);

        Assertions.assertThat(result).isFalse();
    }

    @Test
    void validateVerifiablePresentation_vp_claim_with_verifiableCredential_claim_with_Type_list_elements_are_not_all_of_type_String_throws_InvalidCredentialTypeException_and_return_false() {
        String vpClaimWithVcJwtFormat = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQ6a2V5OnpEbmFlblF6WEthVE5SNlYyaWZyY0VFU042VFR1WWpweWFmUGh0c1pZU3Y0VlJia3IiLCJuYmYiOjE3MTc0MzgwMDMsImlzcyI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sImhvbGRlciI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsImlkIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIiwidHlwZSI6WyJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIl0sInZlcmlmaWFibGVDcmVkZW50aWFsIjpbImV5SmhiR2NpT2lKSVV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUp6ZFdJaU9pSXhNak0wTlRZM09Ea3dJaXdpYm1GdFpTSTZJa3B2YUc0Z1JHOWxJaXdpYVdGMElqb3hOVEUyTWpNNU1ESXlmUS5TZmxLeHdSSlNNZUtLRjJRVDRmd3BNZUpmMzZQT2s2eUpWX2FkUXNzdzVjIl19LCJleHAiOjE3MjAwMzAwMDMsImlhdCI6MTcxNzQzODAwMywianRpIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIn0._tIB_9fsQjZmJV2cgGDWtYXmps9fbLbMDtu8wZhIwC9u6I7RAaR4NK5WrnRC1TIVbQa06ZeneELxc_ktTkdhfA";
        String issuerDid = "did:example:issuer";
        LinkedTreeMap<String, Object> vcMap = new LinkedTreeMap<>();
        vcMap.put("type", Arrays.asList(1,"some-string"));

        Payload payload = mock(Payload.class);
        when(jwtService.getPayloadFromSignedJWT(any(SignedJWT.class))).thenReturn(payload);
        when(jwtService.getClaimFromPayload(eq(payload), eq("iss"))).thenReturn(issuerDid);
        when(jwtService.getVCFromPayload(eq(payload))).thenReturn(vcMap);

        boolean result = vpServiceImpl.validateVerifiablePresentation(vpClaimWithVcJwtFormat);

        Assertions.assertThat(result).isFalse();
    }

    @Test
    void validateVerifiablePresentation_vp_claim_with_verifiableCredential_claim_with_type_key_does_not_map_to_a_List_throws_InvalidCredentialTypeException_and_return_false() {
        String vpClaimWithVcJwtFormat = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQ6a2V5OnpEbmFlblF6WEthVE5SNlYyaWZyY0VFU042VFR1WWpweWFmUGh0c1pZU3Y0VlJia3IiLCJuYmYiOjE3MTc0MzgwMDMsImlzcyI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sImhvbGRlciI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsImlkIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIiwidHlwZSI6WyJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIl0sInZlcmlmaWFibGVDcmVkZW50aWFsIjpbImV5SmhiR2NpT2lKSVV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUp6ZFdJaU9pSXhNak0wTlRZM09Ea3dJaXdpYm1GdFpTSTZJa3B2YUc0Z1JHOWxJaXdpYVdGMElqb3hOVEUyTWpNNU1ESXlmUS5TZmxLeHdSSlNNZUtLRjJRVDRmd3BNZUpmMzZQT2s2eUpWX2FkUXNzdzVjIl19LCJleHAiOjE3MjAwMzAwMDMsImlhdCI6MTcxNzQzODAwMywianRpIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIn0._tIB_9fsQjZmJV2cgGDWtYXmps9fbLbMDtu8wZhIwC9u6I7RAaR4NK5WrnRC1TIVbQa06ZeneELxc_ktTkdhfA";
        String issuerDid = "did:example:issuer";
        LinkedTreeMap<String, Object> vcMap = new LinkedTreeMap<>();
        vcMap.put("type", "invalid-credential-type-instance");

        Payload payload = mock(Payload.class);
        when(jwtService.getPayloadFromSignedJWT(any(SignedJWT.class))).thenReturn(payload);
        when(jwtService.getClaimFromPayload(eq(payload), eq("iss"))).thenReturn(issuerDid);
        when(jwtService.getVCFromPayload(eq(payload))).thenReturn(vcMap);

        boolean result = vpServiceImpl.validateVerifiablePresentation(vpClaimWithVcJwtFormat);

        Assertions.assertThat(result).isFalse();
    }

    @Test
    void validateVerifiablePresentation_vp_claim_with_verifiableCredential_claim_but_VC_from_payload_is_not_a_LinkedTreeMap_throws_InvalidCredentialTypeException_and_return_false() {
        String vpClaimWithVcJwtFormat = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQ6a2V5OnpEbmFlblF6WEthVE5SNlYyaWZyY0VFU042VFR1WWpweWFmUGh0c1pZU3Y0VlJia3IiLCJuYmYiOjE3MTc0MzgwMDMsImlzcyI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sImhvbGRlciI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsImlkIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIiwidHlwZSI6WyJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIl0sInZlcmlmaWFibGVDcmVkZW50aWFsIjpbImV5SmhiR2NpT2lKSVV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUp6ZFdJaU9pSXhNak0wTlRZM09Ea3dJaXdpYm1GdFpTSTZJa3B2YUc0Z1JHOWxJaXdpYVdGMElqb3hOVEUyTWpNNU1ESXlmUS5TZmxLeHdSSlNNZUtLRjJRVDRmd3BNZUpmMzZQT2s2eUpWX2FkUXNzdzVjIl19LCJleHAiOjE3MjAwMzAwMDMsImlhdCI6MTcxNzQzODAwMywianRpIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIn0._tIB_9fsQjZmJV2cgGDWtYXmps9fbLbMDtu8wZhIwC9u6I7RAaR4NK5WrnRC1TIVbQa06ZeneELxc_ktTkdhfA";
        String issuerDid = "did:example:issuer";

        Payload payload = mock(Payload.class);
        when(jwtService.getPayloadFromSignedJWT(any(SignedJWT.class))).thenReturn(payload);
        when(jwtService.getClaimFromPayload(eq(payload), eq("iss"))).thenReturn(issuerDid);
        when(jwtService.getVCFromPayload(eq(payload))).thenReturn("invalid-credential-instance-class");

        boolean result = vpServiceImpl.validateVerifiablePresentation(vpClaimWithVcJwtFormat);

        Assertions.assertThat(result).isFalse();
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

}
