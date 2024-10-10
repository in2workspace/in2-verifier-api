package es.in2.vcverifier.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.exception.JWTParsingException;
import es.in2.vcverifier.exception.UnsupportedDIDTypeException;
import es.in2.vcverifier.model.enums.KeyType;
import es.in2.vcverifier.model.issuer.IssuerCredentialsCapabilities;
import es.in2.vcverifier.model.issuer.TimeRange;
import es.in2.vcverifier.service.impl.VpServiceImpl;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

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

    @Mock
    private SignedJWT signedJWT;

    @InjectMocks
    private VpServiceImpl vpServiceImpl;

    @Test
    void validateVerifiablePresentation_ValidVP_ReturnsTrue() throws Exception {
        // Mock input values
        String validVP = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        SignedJWT signedJWT = mock(SignedJWT.class);
        Payload payload = mock(Payload.class);
        List<String> credentialTypes = List.of("LEARCredentialEmployee");
        String issuerDid = "did:example:issuer";
        String mandateeId = "did:example:mandatee";
        PublicKey publicKey = mock(PublicKey.class);
        List<IssuerCredentialsCapabilities> issuerCapabilities = List.of(
                new IssuerCredentialsCapabilities(TimeRange.builder().build(),"",new ArrayList<>())
        );

        // Mocking methods
        when(jwtService.getPayloadFromSignedJWT(any(SignedJWT.class))).thenReturn(payload);
        when(jwtService.getClaimFromPayload(eq(payload), eq("iss"))).thenReturn(issuerDid);
        when(jwtService.getVCFromPayload(eq(payload))).thenReturn(Map.of("type", credentialTypes));
        when(trustedIssuerListService.getTrustedIssuerListData(issuerDid)).thenReturn(issuerCapabilities);
        when(trustedIssuerListService.getTrustedIssuerListData(mandateeId)).thenReturn(issuerCapabilities);
        when(didService.getPublicKeyFromDid(mandateeId)).thenReturn(publicKey);
        doNothing().when(jwtService).verifyJWTSignature(validVP, publicKey, KeyType.EC);

        // Act
        boolean result = vpServiceImpl.validateVerifiablePresentation(validVP);

        // Assert
        assertTrue(result);
        verify(jwtService, times(
                1)).getPayloadFromSignedJWT(any(SignedJWT.class));
        verify(jwtService, times(1)).verifyJWTSignature(validVP, publicKey, KeyType.EC);
    }

    @Test
    void validateVerifiablePresentation_vp_claim_with_verifiableCredential_claim_no_string_format_throws_CredentialException_and_return_false() {
        String vpClaimWithVcNotStringFormat = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQ6a2V5OnpEbmFlblF6WEthVE5SNlYyaWZyY0VFU042VFR1WWpweWFmUGh0c1pZU3Y0VlJia3IiLCJuYmYiOjE3MTc0MzgwMDMsImlzcyI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sImhvbGRlciI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsImlkIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIiwidHlwZSI6WyJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIl0sInZlcmlmaWFibGVDcmVkZW50aWFsIjpbMV19LCJleHAiOjE3MjAwMzAwMDMsImlhdCI6MTcxNzQzODAwMywianRpIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIn0.K-bG85t--QMmOumsZsNbk7Vm62AUsl8kgDxwH3G9---Eb7xfX0NkVuq1r2iTh-H2uRNcpmnao03Y8fbrnYVqFA";

        boolean result = vpServiceImpl.validateVerifiablePresentation(vpClaimWithVcNotStringFormat);

        assertFalse(result);
    }

    @Test
    void validateVerifiablePresentation_vp_claim_with_verifiableCredential_claim_is_not_found_throws_CredentialException_and_return_false() {
        String vpClaimWithVcArrayEmpty = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQ6a2V5OnpEbmFlblF6WEthVE5SNlYyaWZyY0VFU042VFR1WWpweWFmUGh0c1pZU3Y0VlJia3IiLCJuYmYiOjE3MTc0MzgwMDMsImlzcyI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sImhvbGRlciI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsImlkIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIiwidHlwZSI6WyJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIl0sInZlcmlmaWFibGVDcmVkZW50aWFsIjpbXX0sImV4cCI6MTcyMDAzMDAwMywiaWF0IjoxNzE3NDM4MDAzLCJqdGkiOiI0MWFjYWRhMy02N2I0LTQ5NGUtYTZlMy1lMDk2NjQ0OWYyNWQifQ.kR4ob7mBGb246EpUYpMRKaESEqGc7yZaNnyoZpkxbMrF_bgC9VLRmMagsHP4DXfl7f8XyBUKFyUcda2PUPs-bA";

        boolean result = vpServiceImpl.validateVerifiablePresentation(vpClaimWithVcArrayEmpty);

        assertFalse(result);
    }

    @Test
    void validateVerifiablePresentation_vp_claim_with_verifiableCredential_claim_is_not_an_array_throws_CredentialException_and_return_false() {
        String vpClaimWithVcNotArrayFormat = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQ6a2V5OnpEbmFlblF6WEthVE5SNlYyaWZyY0VFU042VFR1WWpweWFmUGh0c1pZU3Y0VlJia3IiLCJuYmYiOjE3MTc0MzgwMDMsImlzcyI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sImhvbGRlciI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsImlkIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIiwidHlwZSI6WyJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIl0sInZlcmlmaWFibGVDcmVkZW50aWFsIjoibm90LWFycmF5LWZvcm1hdCJ9LCJleHAiOjE3MjAwMzAwMDMsImlhdCI6MTcxNzQzODAwMywianRpIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIn0.0Jpm4g5IUBnZRH5Zf1FSs0nSJmdD9dQncchlFJoqT_tDU733rXLT7UbD0f4KIfwPPZn_APKNt-h5ziTQjgXJiw";

        boolean result = vpServiceImpl.validateVerifiablePresentation(vpClaimWithVcNotArrayFormat);

        assertFalse(result);
    }

    @Test
    void validateVerifiablePresentation_vp_claim_without_verifiableCredential_claim_inside_throws_JWTClaimMissingException_and_return_false() {
        String vpClaimNotValidObject = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJ2cCI6e319.hLaehswoW9QiU_FmLGCDZIPOvnNOvn2HsOCs9lKhHUE";

        boolean result = vpServiceImpl.validateVerifiablePresentation(vpClaimNotValidObject);

        assertFalse(result);
    }

    @Test
    void validateVerifiablePresentation_vp_claim_not_valid_object_throws_JWTClaimMissingException_and_return_false() {
        String vpClaimNotValidObject = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJ2cCI6ImludmFsaWRWcEZvcm1hdCJ9.5-6R9OxqX7lXEEqVL_12Bf0UODXnkPtrt_ntoD2IrPQ";

        boolean result = vpServiceImpl.validateVerifiablePresentation(vpClaimNotValidObject);

        assertFalse(result);
    }

    @Test
    void validateVerifiablePresentation_invalidVP_throws_JWTClaimMissingException_and_return_false() {
        String jwtWithoutVpClaim = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

        boolean result = vpServiceImpl.validateVerifiablePresentation(jwtWithoutVpClaim);

        assertFalse(result);
    }

    @Test
    void validateVerifiablePresentation_invalidVP_throws_JWTParsingException_and_return_false() {
        String invalidVP = "invalidVPJWT";

        boolean result = vpServiceImpl.validateVerifiablePresentation(invalidVP);

        assertFalse(result);
    }

//    @Test
//    void validateVerifiablePresentation_InvalidMandateeId_ThrowsException() throws Exception {
//        // Mock input values
//        String validVP = "validVPJWT";
//        SignedJWT signedJWT = mock(SignedJWT.class);
//        Payload payload = mock(Payload.class);
//        List<String> credentialTypes = List.of("LEARCredentialEmployee");
//        String issuerDid = "did:example:issuer";
//        String invalidMandateeId = "did:example:invalidMandatee";
//        PublicKey publicKey = mock(PublicKey.class);
//        List<IssuerCredentialsCapabilities> issuerCapabilities = List.of(
//                new IssuerCredentialsCapabilities("LEARCredentialEmployee")
//        );
//
//        // Mocking methods
//        when(jwtService.getPayloadFromSignedJWT(any(SignedJWT.class))).thenReturn(payload);
//        when(jwtService.getClaimFromPayload(eq(payload), eq("iss"))).thenReturn(issuerDid);
//        when(jwtService.getVCFromPayload(eq(payload))).thenReturn(Map.of("type", credentialTypes));
//        when(trustedIssuerListService.getTrustedIssuerListData(issuerDid)).thenReturn(issuerCapabilities);
//        when(trustedIssuerListService.getTrustedIssuerListData(invalidMandateeId)).thenThrow(new Exception("Mandatee ID not found"));
//
//        // Act & Assert
//        assertFalse(vpServiceImpl.validateVerifiablePresentation(validVP));
//    }
//
//    @Test
//    void validateVerifiablePresentation_VPVerificationFails_ReturnsFalse() throws Exception {
//        // Mock input values
//        String validVP = "validVPJWT";
//        SignedJWT signedJWT = mock(SignedJWT.class);
//        Payload payload = mock(Payload.class);
//        List<String> credentialTypes = List.of("LEARCredentialEmployee");
//        String issuerDid = "did:example:issuer";
//        String mandateeId = "did:example:mandatee";
//        PublicKey publicKey = mock(PublicKey.class);
//        List<IssuerCredentialsCapabilities> issuerCapabilities = List.of(
//                new IssuerCredentialsCapabilities("LEARCredentialEmployee")
//        );
//
//        // Mocking methods
//        when(jwtService.getPayloadFromSignedJWT(any(SignedJWT.class))).thenReturn(payload);
//        when(jwtService.getClaimFromPayload(eq(payload), eq("iss"))).thenReturn(issuerDid);
//        when(jwtService.getVCFromPayload(eq(payload))).thenReturn(Map.of("type", credentialTypes));
//        when(trustedIssuerListService.getTrustedIssuerListData(issuerDid)).thenReturn(issuerCapabilities);
//        when(trustedIssuerListService.getTrustedIssuerListData(mandateeId)).thenReturn(issuerCapabilities);
//        when(didService.getPublicKeyFromDid(mandateeId)).thenReturn(publicKey);
//        when(jwtService.verifyJWTSignature(validVP, publicKey, KeyType.EC)).thenReturn(false); // Simulate failed signature verification
//
//        // Act
//        boolean result = vpServiceImpl.validateVerifiablePresentation(validVP);
//
//        // Assert
//        assertFalse(result);
//    }

}
