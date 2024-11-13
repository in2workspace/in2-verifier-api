package es.in2.verifier;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.SignedJWT;
import es.in2.verifier.domain.exception.JWTVerificationException;
import es.in2.verifier.domain.util.UVarInt;
import org.bitcoinj.base.Base58;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.util.AssertionErrors.assertTrue;

class DIDTest {

    // https://www.scottbrady91.com/tools/jwt

    @Test
    void getPrivateKeyToHex() {
        // Claves en formato Base64 URL-safe

        String privateKeyBase64 = "YkV0K8F8AvI6Cy90j1jJ2f99UO2HuLClMrB9savkfRg";
        String publicKeyXBase64 = "9SBwGwze-1G6v6vfR-2pEwxvGbXyo7w1rdSUb9IrTfk";
        String publicKeyYBase64 = "UydbH61G-MAcl6AlEtBMo_kO4pS2fntNeqfXgi9bb2w";

        // Convertir las claves de Base64 URL-safe a bytes y luego a hexadecimal
        String privateKeyHex = base64UrlToHex(privateKeyBase64);
        String publicKeyXHex = base64UrlToHex(publicKeyXBase64);
        String publicKeyYHex = base64UrlToHex(publicKeyYBase64);

        // Mostrar las claves en hexadecimal
        System.out.println("Clave privada (hex): " + privateKeyHex);
        System.out.println("Clave pública X (hex): " + publicKeyXHex);
        System.out.println("Clave pública Y (hex): " + publicKeyYHex);
    }

    // Método para convertir Base64 URL-safe a Hexadecimal
    public static String base64UrlToHex(String base64Url) {
        // Decodificar Base64 URL-safe a bytes
        byte[] bytes = Base64.getUrlDecoder().decode(base64Url);

        // Convertir bytes a hexadecimal
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }

    @Test
    void generateDid() throws NoSuchAlgorithmException, InvalidKeySpecException, JOSEException {
        ECKey ecKey = generateECKeyAndDidKey();
        System.out.println("Private Key - d: " + ecKey.getD() + " x: " + ecKey.getX() + " y: " + ecKey.getY());
        String didKey = getDidKeyFromPublicKey(ecKey.toECPublicKey());
        // Generate a JWT to test M2M
        ECKey ecPublicJWK = ecKey.toPublicJWK();
        JWSSigner signer = new ECDSASigner(ecKey);
        Payload payload = new Payload(Map.of(
                "iss", didKey,
                "iat", 1725951134,
                "exp", 1760079134,
                "aud", "http://localhost:9000",
                "sub", didKey,
                "vp_token", "LEARCredentialMachine in JWT",
                "jti", "6bede557-46d3-4a6a-837d-2080e4c38222"
        ));
        JWSObject jwsObject = new JWSObject(
                new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(ecKey.getKeyID()).build(),
                payload);
        // Compute the EC signature
        jwsObject.sign(signer);
        // Serialize the JWS to compact form
        String jwtBearer = jwsObject.serialize();
        System.out.println("JWT: " + jwtBearer);
        // The recipient creates a verifier with the public EC key
        JWSVerifier verifier = new ECDSAVerifier(ecPublicJWK);
        // Verify the EC signature
        assertTrue("ES256 signature verified", jwsObject.verify(verifier));
        assertEquals(payload.toString(), jwsObject.getPayload().toString());
    }

    @Test
    void generateClientAssertionJWT() throws NoSuchAlgorithmException, InvalidKeySpecException, JOSEException {

        ECKey ecKey = generateECKeyAndDidKey();
        String didKey = getDidKeyFromPublicKey(ecKey.toECPublicKey());
        System.out.println("Private Key - d: " + ecKey.getD() + " x: " + ecKey.getX() + " y: " + ecKey.getY());
        // Generate a JWT to test M2M
        ECKey ecPublicJWK = ecKey.toPublicJWK();
        JWSSigner signer = new ECDSASigner(ecKey);
        Payload payload = new Payload(Map.of(
                "iss", didKey,
                "iat", 1725951134,
                "exp", 1760079134,
                "aud", "http://localhost:9000",
                "sub", didKey,
                "vp_token", "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQ6a2V5OnpEbmFlcGJRa0xueXdYNEdIc25wVHVHUWtCSHRKNFVuR005N3RzN1h1TTI3M0wxaWgiLCJuYmYiOjE3MTc0MzgwMDMsImlzcyI6ImRpZDprZXk6ekRuYWVwYlFrTG55d1g0R0hzbnBUdUdRa0JIdEo0VW5HTTk3dHM3WHVNMjczTDFpaCIsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sImhvbGRlciI6ImRpZDprZXk6ekRuYWVwYlFrTG55d1g0R0hzbnBUdUdRa0JIdEo0VW5HTTk3dHM3WHVNMjczTDFpaCIsImlkIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIiwidHlwZSI6WyJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIl0sInZlcmlmaWFibGVDcmVkZW50aWFsIjpbImV5SjBlWEFpT2lKS1YxUWlMQ0poYkdjaU9pSkZVekkxTmlJc0luZzFZeUk2V3lKTlNVbEhUM3BEUTBKVFQyZEJkMGxDUVdkSlZVNW1PRE5rTkVwamRtTlRiMFZGTUU4MVpERjJRVFJDUWxWeGMzZEVVVmxLUzI5YVNXaDJZMDVCVVVWT1FsRkJkMmRpUlhoSmFrRm5RbWRPVmtKQlRVMUhWVkpLVWpCc1ZWSlZkMmRXUmsxblVWVlNWMUZWTlVSU1ZWRm5VVEJGWjFKNlJYaEZha0ZSUW1kT1ZrSkJWVlJEVlVrd1RucFJNRTU2VlRKTlJFVnlUVU5yUjBFeFZVVkRkM2RwVWtWc1NGTldVa1pVUTBKVlZYbENSRkpXU2xWVFZWcEtVVEJHVlZOVk9VOUpSVVpXVmtWb1VGVnJiRlZYVkVWdlRVTlpSMEV4VlVWRFozZG1Va1ZzU0ZOV1VrWlVRMEpRVkdsQ1ZWVnNWbFJXUlZaRlNVWk9SbFZzV2twUk1GWlVTVVpPVFZaVVJWUk5Ra1ZIUVRGVlJVSjNkMHRXYlVaellrZEdhMkl5ZUhCYVJFVk1UVUZyUjBFeFZVVkNhRTFEVWxaTmQwaG9ZMDVOYWxGM1RsUkplRTFFYTNwTlZFRjZWMmhqVGsxcVkzZE9WRWw0VFVScmVrMVVRWGxYYWtOQ2RYcEZaRTFDYzBkQk1WVkZRWGQzVlU1VVdURk9hbFV5VGxSYVVVbEZjR3hqTTFaNlNVWktNV0ZZYjNoSFJFRlhRbWRPVmtKQlZWUkVNR3hGVVRCV1ZFeFVWVEpPVkZreFRtcFZNbFZFUlU5TlFYZEhRVEZWUlV0bmQwWlRhMVpVVmxaTmVFUlVRVXhDWjA1V1FrRlJUVUpHU2xaVFZtOTRTSHBCWkVKblRsWkNRWE5OUm10U1VGUlZWV2RSTTBwc1drZFdkV1JIYkdoaVEwSktZek5PTVZwWVNYaEhSRUZYUW1kT1ZrSkhSVTFFTVZwQ1ZrVldWRXhXUlhkTlJFRjNUVVJCZDFOcVJWcE5RbU5IUVRGVlJVTm5kMUZTUlRsT1VsTkNUbGxZU25KYVdGSjNZa2RHYWxwVVJVeE5RV3RIUVRGVlJVSm9UVU5TVmsxM1oyZEphVTFCTUVkRFUzRkhVMGxpTTBSUlJVSkJVVlZCUVRSSlEwUjNRWGRuWjBsTFFXOUpRMEZSUkZwNE9WWkdWSEZJWVZWQlZsUkZXR2cxYzB3MVIzWnZjSFpDUjFNMGF6VmtaMllyZEdKQ1JsQjFNMjg1S3k4dlNtTXZTa1JIVXpaU2F6WkRNMlpqTmtzdmVXaG1VRUpEVVhkRVRYZGxZa2MyUVZwQmJWVXpURGhZTVdWc2JIWkJSVzVaUWpKd2QxTmhkbWRpY0hGTE1rUmFiM2RVZEdsaU0waFlVMEZISzFkQlR6SlFjMDQwWVZsVVNIRjBUa3M0WjFweWJGVkZObGc1WkcxNmFGUlNRVWx4YzB4NU1YWkRRWFp1VjB4cFFqVXpkU3N2ZFc1Sk1rNDFTV3BtVjFSWWRTdHZNVTk0YjFVck9YWm5lSGcxVldkNmQyWmFWVTVpYVV4a1dVSmFRMU0zTlVwR2RXOUJWRlZaZWtSUmJtY3ZVM2t2TlhNdlEzWXdabFZ5U2xSMU1VbzJZM1V5VURKM0x6VjVNbVJIUjB3ME1sQlJSV1ZuWVhsWmJTODJXVGhCWWpSb2N6RkZVMWtyT1V4RFNtZFRNbkkyUVROWWJGTkliV3hPYm1OVmQxVjNWbVJNVGxCMU1HeDJORUZyVFV0dlJITXdkSEJPV20xbE1tTjJOR2Q0YTA1dFZGazVjalYwYUVkT1RIcENjVkZqUzFOb05WZFVLMDFSVEdWMFRtbGxja28wYVhCUlVYZ3hTSGhOTkVaUlNYQnJibmN3U1hvNFpUZFJaaXRNVDJGTU5rWkJZbEYyV0RWRVVERjJRbWx4VVhKMlRFeEhlaXNyTURSR1owbFZlREpaVmxWTVpXRjBNRGRPTUdSbGRXaHJieXRSVGpaM1MyZ3lNRGg2Wm1wd1FWVktURFJWV0VObU1GcGhVMjlTUm1Gd2VDdFNVRkZDWmpsT2RHcFRlRWMzVmt0TkszTlFOalpwY0ZoUU5XbDRkRmhDYTNGT09FVllZblZPVlVkWGEyRkhjMDFNVm1vNFZIRnNaM3A2ZGpGd1lYUmxiRWxIZUZsSFVIVjZlak16Y3k5NFQwOW5URGR6TjBnM1MydE5iREJ2ZDJaRGNWWkdURVZZUzFSak9FRlBTR2hvTkZadE5pdGpkVXBZUW5oU1UyRkpaamRWV1ZoTGJraG9ZVlF3U3pWck0zWnVTSG9yTDBSSVkxaElXR28xVXpkUFJuVkNWa295V2l0UE1XRlRNemRvWXlzM1pYcGxaV0ZSU1VSQlVVRkNielJKUWxCVVEwTkJWR3QzUkVGWlJGWlNNRlJCVVVndlFrRkpkMEZFUVdaQ1owNVdTRk5OUlVkRVFWZG5RbEZUVXpBelJXa3ZTVmN3WjNSNmFWSkNTM2hVTUVVeU9HeERkbFJDYzBKblozSkNaMFZHUWxGalFrRlJVbWROUmpSM1RtZFpTVXQzV1VKQ1VWVklUVUZMUjB0dGFEQmtTRUUyVEhrNWQyRXlhM1ZhUjJ4dVlWaFNiR0pJVW5wTWJWWjZUREJTU2xJd2JGVlNWWGhWVlRCR1JWWnJZM2hNYlU1NVpFUkJhMEpuWjNKQ1owVkdRbEZqZDBGWldWbGhTRkl3WTBSdmRrd3lPV3BqTTBGMVdrZHNibUZZVW14aVNGSjZURzFXZWsxQk9FZERVM05IUVZGVlJrSjZRVUpDVVZGRFFsRkJkMGhSV1VSV1VqQnNRa0paZDBaQldVbExkMWxDUWxGVlNFRjNTVWREUTNOSFFWRlZSa0ozVFVWTlJITkhRVEZWWkVoM1VUQk5SRWwzVFV0QmRXOURlVWRMYldnd1pFaEJOa3g1T1dwamJYZDFZMGQwY0V4dFVuQmFNbXd3V2xkNE1HTjVOV3hqZVRsRlZrWk9RbHBJV2tSUlZXTjRURzFPZVdKRVFXUkNaMDVXU0ZFMFJVWm5VVlZLUkhaVGRYSklSR1o0VGl0T2FXODVURkJHUWtwclVrTk1iemgzUkdkWlJGWlNNRkJCVVVndlFrRlJSRUZuWWtGTlFUQkhRMU54UjFOSllqTkVVVVZDUkZGVlFVRTBTVUpCVVVGYVJEbE5XVlpMWlc4M1RETnpia2Q2VEZCR1REWnBXSE5oWlVWT1VVUk5iMUJtU1hCT1NHTXZNM0pNUlZkWVlrTjNSek5EUTNoemJGVnFVbWt3Y0cxSlVrRjRUMng2TDFSUE1uYzFNRms1V0d0SGFuVTRkSGg1ZEVOeVRqVXlaM3BSYjBkNmRrWktZWEEwUjBRcll6Vk5ORlozVVdZMVoyaEVlVkZHV1ZScFUxcEJNVlI2YVVsTGJqaExValZCWm10a2VXUkRSVWxRVWpFNFRqbDVjRVF6ZUZFMVNVMDVhVTk0ZEdwR1FXVnVVMm94V0hkWFQyRTBiSGhVVVVSdlJERmhOaTlIY1ZOa1RFMTJZMkV5U2xsMmNURnBOWEZTZFM5bGNqUjJUbEZZYTA1VGVtbGFUSEZ2VlVkc2NHTm5jMlZ0TVRSdlYzTlRaRFpoWW14YVpreE1iR1F2VW5SRmRYUkhPVWhhYVN0a1JXNXVaMjFDVXpOWE1pOVZNRXgxWm1aMFVEWkhNbmRGWVZOcGQwVlBaMUZuVUdSRWRXdG1MMWxWYjNGd2VGWTFhM0ZxUm5Kak4wdEtkREJ4Vm1wNU9IbE1URk5oUlNKZGZRLmV5SnpkV0lpT2lKa2FXUTZhMlY1T25wRWJtRmxVMmRxVGpoVWNVZEhjV1Z5UlUxVWJYbHZlVlZEUm1zemRVdG5NMWhHVW1oek0wTjRTMk5LUjNWTVFrZ2lMQ0p1WW1ZaU9qRTNNRFF3T1RZd01EQXNJbWx6Y3lJNkltUnBaRHBsYkhOcE9sWkJWRVZUTFZFd01EQXdNREF3U2lJc0ltVjRjQ0k2TVRjek5UWTRPVFUwTUN3aWFXRjBJam94TnpBME1EazJNREF3TENKMll5STZleUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzZDNkeTVsZG1sa1pXNWpaV3hsWkdkbGNpNWxkUzh5TURJeUwyTnlaV1JsYm5ScFlXeHpMMjFoWTJocGJtVXZkakVpWFN3aWFXUWlPaUk0WXpkaE5qSXhNeTAxTkRSa0xUUTFNR1F0T0dVelpDMWlOREZtWVRrd01Ea3hPVGdpTENKMGVYQmxJanBiSWxabGNtbG1hV0ZpYkdWRGNtVmtaVzUwYVdGc0lpd2lURVZCVWtOeVpXUmxiblJwWVd4TllXTm9hVzVsSWwwc0ltbHpjM1ZsY2lJNmV5SnBaQ0k2SW1ScFpEcGxiSE5wT2xaQlZFVlRMVkV3TURBd01EQXdTaUo5TENKcGMzTjFZVzVqWlVSaGRHVWlPaUl5TURJMExUQXhMVEF4VkRBNE9qQXdPakF3TGpBd01EQXdNREF3TUZvaUxDSjJZV3hwWkVaeWIyMGlPaUl5TURJMExUQXhMVEF4VkRBNE9qQXdPakF3TGpBd01EQXdNREF3TUZvaUxDSmxlSEJwY21GMGFXOXVSR0YwWlNJNklqSXdNalF0TVRJdE16RlVNak02TlRrNk1EQXVNREF3TURBd01EQXdXaUlzSW1OeVpXUmxiblJwWVd4VGRXSnFaV04wSWpwN0ltMWhibVJoZEdVaU9uc2lhV1FpT2lJM1ltWTFOV1F5WlMwMU1qUTNMVFEzTVRRdE9URmtNUzA0WlRKbU9HTmlOek13WkRFaUxDSnNhV1psWDNOd1lXNGlPbnNpYzNSaGNuUkVZWFJsVkdsdFpTSTZJakl3TWpRdE1ERXRNREZVTURnNk1EQTZNREF1TURBd01EQXdNREF3V2lJc0ltVnVaRVJoZEdWVWFXMWxJam9pTWpBeU5DMHhNaTB6TVZReU16bzFPVG93TUM0d01EQXdNREF3TURCYUluMHNJbTFoYm1SaGRHVmxJanA3SW1sa0lqb2laR2xrT210bGVUcDZSRzVoWlZObmFrNDRWSEZIUjNGbGNrVk5WRzE1YjNsVlEwWnJNM1ZMWnpOWVJsSm9jek5EZUV0alNrZDFURUpJSWl3aWMyVnlkbWxqWlU1aGJXVWlPaUpKYzNOMVpYSkJVRWtpTENKelpYSjJhV05sVkhsd1pTSTZJa0ZRU1NCVFpYSjJaWElpTENKMlpYSnphVzl1SWpvaWRqRXVNQ0lzSW1SdmJXRnBiaUk2SW1oMGRIQnpPaTh2YVhOemRXVnlMbVJ2YldVdGJXRnlhMlYwY0d4aFkyVXViM0puSWl3aWFYQkJaR1J5WlhOeklqb2lNVEkzTGpBdU1DNHhJaXdpWkdWelkzSnBjSFJwYjI0aU9pSkJVRWtnZEc4Z2FYTnpkV1VnVm1WeWFXWnBZV0pzWlNCRGNtVmtaVzUwYVdGc2N5SXNJbU52Ym5SaFkzUWlPbnNpWlcxaGFXd2lPaUprYjIxbGMzVndjRzl5ZEVCcGJqSXVaWE1pTENKd2FHOXVaU0k2SWlzek5EazVPVGs1T1RrNU9TSjlmU3dpYldGdVpHRjBiM0lpT25zaVkyOXRiVzl1VG1GdFpTSTZJalUyTlRZMU5qVTJVQ0JLWlhOMWN5QlNkV2w2SWl3aVkyOTFiblJ5ZVNJNklrVlRJaXdpWlcxaGFXeEJaR1J5WlhOeklqb2lhbVZ6ZFhNdWNuVnBla0JwYmpJdVpYTWlMQ0p2Y21kaGJtbDZZWFJwYjI0aU9pSkpUaklzSUVsdVoyVnVhV1Z5dzYxaElHUmxJR3hoSUVsdVptOXliV0ZqYWNPemJpd2dVeTVNTGlJc0ltOXlaMkZ1YVhwaGRHbHZia2xrWlc1MGFXWnBaWElpT2lKV1FWUkZVeTFSTURBd01EQXdNRW9pTENKelpYSnBZV3hPZFcxaVpYSWlPaUpKUkVORlV5MDFOalUyTlRZMU5sQWlmU3dpY0c5M1pYSWlPbHQ3SW1sa0lqb2lNV0V5TmpZNE5qVXRPV05rWVMwME1tTTBMVGc0TkdZdFltUXhPR0UzT1dVNFltWmtJaXdpWkc5dFlXbHVJam9pUkU5TlJTSXNJbVoxYm1OMGFXOXVJam9pVEc5bmFXNGlMQ0poWTNScGIyNGlPaUp2YVdSalgyMHliU0o5TEhzaWFXUWlPaUpoTkdaa05ESm1aUzFqWldSbExUUmxORGd0T0RGaE1TMDBPVFkyWkdVeU1qRmpOakFpTENKa2IyMWhhVzRpT2lKRVQwMUZJaXdpWm5WdVkzUnBiMjRpT2lKRFpYSjBhV1pwWTJGMGFXOXVJaXdpWVdOMGFXOXVJam9pY0c5emRGOTJaWEpwWm1saFlteGxYMk5sY25ScFptbGpZWFJwYjI0aWZTeDdJbWxrSWpvaU4yWTFNalE0TmpjdE5HRmlaQzAwWVRrMUxXRTJPRFF0TTJReVpETmhPR1V5WWpKaklpd2laRzl0WVdsdUlqb2lSRTlOUlNJc0ltWjFibU4wYVc5dUlqb2lTWE56ZFdGdVkyVWlMQ0poWTNScGIyNGlPaUpwYzNOMVpWOTJZeUo5WFN3aWMybG5ibVZ5SWpwN0ltTnZiVzF2Yms1aGJXVWlPaUkxTmpVMk5UWTFObEFnU21WemRYTWdVblZwZWlJc0ltTnZkVzUwY25raU9pSkZVeUlzSW1WdFlXbHNRV1JrY21WemN5STZJbXBsYzNWekxuSjFhWHBBYVc0eUxtVnpJaXdpYjNKbllXNXBlbUYwYVc5dUlqb2lTVTR5TENCSmJtZGxibWxsY3NPdFlTQmtaU0JzWVNCSmJtWnZjbTFoWTJuRHMyNHNJRk11VEM0aUxDSnZjbWRoYm1sNllYUnBiMjVKWkdWdWRHbG1hV1Z5SWpvaVZrRlVSVk10VVRBd01EQXdNREJLSWl3aWMyVnlhV0ZzVG5WdFltVnlJam9pU1VSRFJWTXROVFkxTmpVMk5UWlFJbjE5Zlgwc0ltcDBhU0k2SWpjME5Ua3pPV013TFRSa1ltWXRORFV4WWkxaE1qRXpMVE15WkdZMFpqQTNZekkyTkNKOS5DMzdwX1dLcks1TFp1LTlFLWtGdWJVZm56QWxpY3dhT2ExRWF0ZWxGWXdaUDF1bWVQNWFZbXVxbmozb1hiMm9TRlJzTDgzSmhzRThlanhmRzVpbGtBZyJdfSwiZXhwIjoxNzIwMDMwMDAzLCJpYXQiOjE3MTc0MzgwMDMsImp0aSI6IjQxYWNhZGEzLTY3YjQtNDk0ZS1hNmUzLWUwOTY2NDQ5ZjI1ZCJ9.E2f_94-uCOCwhitUWE-Y5fgNrPyCA8frQm89QR18xg38-eXwA3hQKL_OB-zWTphodHE8poT_9KaSEu1-9GSZdg",
                "jti", "6bede557-46d3-4a6a-837d-2080e4c38222"
        ));
        JWSObject jwsObject = new JWSObject(
                new JWSHeader.Builder(JWSAlgorithm.ES256)
//                        .keyID(ecKey.getKeyID())
                        .type(JOSEObjectType.JWT)
                        .build(),
                payload);
        // Compute the EC signature
        jwsObject.sign(signer);
        // Serialize the JWS to compact form
        String jwtBearer = jwsObject.serialize();
        System.out.println("JWT: " + jwtBearer);
        // The recipient creates a verifier with the public EC key
        JWSVerifier verifier = new ECDSAVerifier(ecPublicJWK);
        // Verify the EC signature
        assertTrue("ES256 signature verified", jwsObject.verify(verifier));
        assertEquals(payload.toString(), jwsObject.getPayload().toString());

    }

    @Test
    void generateJWT2() throws NoSuchAlgorithmException, InvalidKeySpecException, JOSEException {
        Map<String, Object> vp = Map.of(
                "@context", List.of("https://www.w3.org/2018/credentials/v1"),
                "holder", "did:key:zDnaepbQkLnywX4GHsnpTuGQkBHtJ4UnGM97ts7XuM273L1ih",
                "id", "urn:uuid:41acada3-67b4-494e-a6e3-e0966449f25d",
                "type", List.of("VerifiablePresentation"),
                "verifiableCredential", List.of(
                        "eyJhbGciOiJSUzI1NiIsImN0eSI6Impzb24iLCJraWQiOiJNSUhRTUlHM3BJRzBNSUd4TVNJd0lBWURWUVFEREJsRVNVZEpWRVZNSUZSVElFRkVWa0ZPUTBWRUlFTkJJRWN5TVJJd0VBWURWUVFGRXdsQ05EYzBORGMxTmpBeEt6QXBCZ05WQkFzTUlrUkpSMGxVUlV3Z1ZGTWdRMFZTVkVsR1NVTkJWRWxQVGlCQlZWUklUMUpKVkZreEtEQW1CZ05WQkFvTUgwUkpSMGxVUlV3Z1QwNGdWRkpWVTFSRlJDQlRSVkpXU1VORlV5QlRURlV4RXpBUkJnTlZCQWNNQ2xaaGJHeGhaRzlzYVdReEN6QUpCZ05WQkFZVEFrVlRBaFJraVFqbVlLNC95SzlIbGdrVURVNHoyZEo5OWc9PSIsIng1dCNTMjU2IjoidEZHZ19WWHVBdUc3NTZpUG52aWVTWjQ2ajl6S3VINW5TdmJKMHA5cFFaUSIsIng1YyI6WyJNSUlIL1RDQ0JlV2dBd0lCQWdJVVpJa0k1bUN1UDhpdlI1WUpGQTFPTTluU2ZmWXdEUVlKS29aSWh2Y05BUUVOQlFBd2diRXhJakFnQmdOVkJBTU1HVVJKUjBsVVJVd2dWRk1nUVVSV1FVNURSVVFnUTBFZ1J6SXhFakFRQmdOVkJBVVRDVUkwTnpRME56VTJNREVyTUNrR0ExVUVDd3dpUkVsSFNWUkZUQ0JVVXlCRFJWSlVTVVpKUTBGVVNVOU9JRUZWVkVoUFVrbFVXVEVvTUNZR0ExVUVDZ3dmUkVsSFNWUkZUQ0JQVGlCVVVsVlRWRVZFSUZORlVsWkpRMFZUSUZOTVZURVRNQkVHQTFVRUJ3d0tWbUZzYkdGa2IyeHBaREVMTUFrR0ExVUVCaE1DUlZNd0hoY05NalF3TmpJeE1EWTFOelUwV2hjTk1qY3dOakl4TURZMU56VXpXakNCcXpFVk1CTUdBMVVFQXd3TVdrVlZVeUJQVEVsTlVFOVRNUmd3RmdZRFZRUUZFdzlKUkVORlZTMDVPVGs1T1RrNU9WQXhEVEFMQmdOVkJDb01CRnBGVlZNeEVEQU9CZ05WQkFRTUIwOU1TVTFRVDFNeEh6QWRCZ05WQkFzTUZrUlBUVVVnUTNKbFpHVnVkR2xoYkNCSmMzTjFaWEl4R0RBV0JnTlZCR0VNRDFaQlZFVlZMVUk1T1RrNU9UazVPVEVQTUEwR0ExVUVDZ3dHVDB4SlRWQlBNUXN3Q1FZRFZRUUdFd0pGVlRDQ0FpSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnSVBBRENDQWdvQ2dnSUJBTERkMGNGZ3A2dzdqV0dVNW9OU3hBWXVQejlodzMwWHdtQ3AxTldieTh4STBPN2I5blUwT0JwTTR1ZWRDKzdoSDd5Uk51ek9VTzF3S1IwZkpJcVkyc3picTExblZwNnNDTWl1eVlzb0d4NXJNQ3RMM3Y5TFBFdnU2MXhER0xRYVlBZnF0ZjVhTXdHL0QvOTQzdnUvTzJYZWQyc1VOYnIrZDFIYjZlUHVIRzU5ZS9YekRraTBuZUtPOHJSUllRakVlSzhDek50Z3N6NUN4cFBtZ3g5ZUVqMEYwZTEzRjErbzB5VGwzYUhET1FvVUErUWhjQzRYc2UzQkN0TXZnRTl1WTdWKzNlRUhFR2h5bUJjeldtbHVYeGpRMjJDZlREWFZvKzFEa0U3SWhkZU9pdGRBa2txT056VVRzVGwxa2gwTlByNDJaall3K1JaK3EybTI4QTYvbTVEbzBUdGlIaDFML2dHZkVaZjhBRzJUWWt6alhkSGEvdWRFY1hrTmlBeVpGZEo3RDlIYzZwZUhXdlFDZ2VES1dVakVtcExiMkx1c2pqVmRTYTdRc2hZbHZYS3I2b3FRcW5qZ0tOWTMwSXBvOTF2SUxZQ243MTJHRHlMR0x1ZEpxUXI0L0s5Y2cwR21sRUI1OGU4ZHdKRlhXK1o2c3lodW9CaEZESkRZNE9oZnFYeVQ2bnNPOEJ1WVl3YmFMQkFIZGprcmt5UUdpTFJDVk5oTDlBeHdBdXlhRkhjeU5ieXo5RDZ0ZUVXSThSWWFMN2JJNStpa0VBVkVJVWdnZlUxK1JCaFQwa3dDbmVTSk5BYUorSnN2WjA1czFNdTFhakZMWVhZMHI5clVlb1cyMkJDSmJuVXEyYjEzdS92dS9hRlZjTkpMdXE3OXp1YWZJUytybXQ2NUFqN3ZBZ01CQUFHamdnSVBNSUlDQ3pBTUJnTlZIUk1CQWY4RUFqQUFNQjhHQTFVZEl3UVlNQmFBRklJVG9hTUNsTTVpRGVBR3RqZFdRWEJjUmE0ck1IUUdDQ3NHQVFVRkJ3RUJCR2d3WmpBK0JnZ3JCZ0VGQlFjd0FvWXlhSFIwY0RvdkwzQnJhUzVrYVdkcGRHVnNkSE11WlhNdlJFbEhTVlJGVEZSVFVWVkJURWxHU1VWRVEwRkhNUzVqY25Rd0pBWUlLd1lCQlFVSE1BR0dHR2gwZEhBNkx5OXZZM053TG1ScFoybDBaV3gwY3k1bGN6Q0J3QVlEVlIwZ0JJRzRNSUcxTUlHeUJnc3JCZ0VFQVlPblVRb0RDekNCb2pBL0JnZ3JCZ0VGQlFjQ0FSWXphSFIwY0hNNkx5OXdhMmt1WkdsbmFYUmxiSFJ6TG1WekwyUndZeTlFU1VkSlZFVk1WRk5mUkZCRExuWXlMakV1Y0dSbU1GOEdDQ3NHQVFVRkJ3SUNNRk1NVVVObGNuUnBabWxqWVdSdklHTjFZV3hwWm1sallXUnZJR1JsSUdacGNtMWhJR1ZzWldOMGNtOXVhV05oSUdGMllXNTZZV1JoSUdSbElIQmxjbk52Ym1FZ1ptbHphV05oSUhacGJtTjFiR0ZrWVRBUEJna3JCZ0VGQlFjd0FRVUVBZ1VBTUIwR0ExVWRKUVFXTUJRR0NDc0dBUVVGQndNQ0JnZ3JCZ0VGQlFjREJEQkNCZ05WSFI4RU96QTVNRGVnTmFBemhqRm9kSFJ3T2k4dlkzSnNNUzV3YTJrdVpHbG5hWFJsYkhSekxtVnpMMFJVVTFGMVlXeHBabWxsWkVOQlJ6RXVZM0pzTUIwR0ExVWREZ1FXQkJSSnRva0hPWEYyMzVVSktZM0tPQVdhZ1NHZExEQU9CZ05WSFE4QkFmOEVCQU1DQnNBd0RRWUpLb1pJaHZjTkFRRU5CUUFEZ2dJQkFGME1nS1NHWXNiaURrUTVCQmZLc1VGWnpBd2xzTDhrRTYzUHlKMFBMajVzT2VUMEZMWTVJeTVmY0U2NmcwWEozSWsvUG0vYTFiK0hCd2l0bkx3ZGRKbVJwWm9ta09RSWxaYXRUQk9tQTlUd2M4OE5MdU5TdTdVM0F5cXV0akRSbFVDOFpGeWRDY1pUalF0bVVIM1FlU0d4RDYvRy82T0JGK2VVY3o1QTVkenJIMGtKNkQrYTQ3MjBjYitkZ01ycTA0OTBVbTVJcExReXRuOG5qSjNSWWtINnhVNmoxdEJpVmsrTVJ4TUZ6bUoxSlpLd1krd2pFdklidlZrVGt0eGRLWVFubFhGL1g2UlhnZjJ0MEJlK0YyRDU0R3pYcWlxeGMvRVVZM3k1Ni9rTUk1OW5ibGdia1ZPYTZHYVd3aUdPNnk1R3h2MVFlUmxVd2Z5TGZRRFR4Ykh6eXBrUysrcG55NXl2OU5kVytQR2loUVZubGFrdkFUS010M1B4WVZyYU91U3NWQVQyVVlVLy9sRGNJWU44Sk94NDB5amVubVVCci8yWE1yeDd2SzhpbkU1SzI0cmg4OXNZUVc3ZkZLM2RmQTRpeTEzblpRc1RzdWlEWVdBZWV6cTlMU3RObE9ncnFxd0RHRDdwLzRzbFh2RlhwTkxtcjlYaXVWRUtXQ0dmSXJnY0tPck5qV3hRREMwV1NsdGtNUFZTZzVrTlMwTW1GYmM0OHB3WXlmR3o2TkUvSmFVNVFzcXdBNnRtR3FLanhOUXJKRGptYXBheFltL3RYSjZhblhjY2sySWVudDRlc241UDhIdE1uK0wzQWQ0RFF4NWlkVWhPQmtsb1NWVlR2dWUvOXgrZTRQWXJDVHNiT3pBa1VtRTl3amFOSStLNW9jWmFvVEhDQTVDNyIsIk1JSUdWVENDQkQyZ0F3SUJBZ0lVRTZwM1hXYXFWOHdpZFQwR2dGZWNxOU1iSGw0d0RRWUpLb1pJaHZjTkFRRU5CUUF3Z2JFeElqQWdCZ05WQkFNTUdVUkpSMGxVUlV3Z1ZGTWdRVVJXUVU1RFJVUWdRMEVnUnpJeEVqQVFCZ05WQkFVVENVSTBOelEwTnpVMk1ERXJNQ2tHQTFVRUN3d2lSRWxIU1ZSRlRDQlVVeUJEUlZKVVNVWkpRMEZVU1U5T0lFRlZWRWhQVWtsVVdURW9NQ1lHQTFVRUNnd2ZSRWxIU1ZSRlRDQlBUaUJVVWxWVFZFVkVJRk5GVWxaSlEwVlRJRk5NVlRFVE1CRUdBMVVFQnd3S1ZtRnNiR0ZrYjJ4cFpERUxNQWtHQTFVRUJoTUNSVk13SGhjTk1qUXdOVEk1TVRJd01EUXdXaGNOTXpjd05USTJNVEl3TURNNVdqQ0JzVEVpTUNBR0ExVUVBd3daUkVsSFNWUkZUQ0JVVXlCQlJGWkJUa05GUkNCRFFTQkhNakVTTUJBR0ExVUVCUk1KUWpRM05EUTNOVFl3TVNzd0tRWURWUVFMRENKRVNVZEpWRVZNSUZSVElFTkZVbFJKUmtsRFFWUkpUMDRnUVZWVVNFOVNTVlJaTVNnd0pnWURWUVFLREI5RVNVZEpWRVZNSUU5T0lGUlNWVk5VUlVRZ1UwVlNWa2xEUlZNZ1UweFZNUk13RVFZRFZRUUhEQXBXWVd4c1lXUnZiR2xrTVFzd0NRWURWUVFHRXdKRlV6Q0NBaUl3RFFZSktvWklodmNOQVFFQkJRQURnZ0lQQURDQ0Fnb0NnZ0lCQU1PUWFCSkdVbkt2eDQwS1pENkVldVlNU3hBQWNjc0h5TkpXNnFNbms2N25PUEhCOTdnalJnbnNKeGVoVThRUGd4aE9iaHE3a1djMDJ2VzhuUUlTMnF5NzBIalcreTZJTWFPdGx5a3NvTlhPY3pRb1pDblZxQklpL2tEc09oRlYxcmNFWGFpQkVUL051SXJTS3ZHWUVJZHpBOUphcVlkZmkvSlEvbHJZYXlEZlAzZDczaHN1cStsSWpOMGQ5aCtwS2NZd0wvbUlJYksvY1F3bGxBVW1kZHJBdzlXRW1xa2wrNVJ1RFdxcGxEV2hodnBHSkZQWHQ0UnFLZ2FhVk41VFV3UzJPR0pTTnFDczZaSSthU2RuZVRnQ3FxUS8vODNoTjlRc20wbUIwTjhOTzlscVNwQ21QT2pZR09UcDdJazhpQjd0ZXgxT055ZVhNSGw5ektEY2lxVjE2MlpScEd0Sm0ycnU4NklVQ1NqUGxzcVRYTW5XMTQyTUt1Z3NXM1g3MVkwcXgzRFJVKzNMd2djSnFhTzFZLzlEMmtRRVFKM3Y1WmVpR1FhdVJXcWZqakFrRVJnaCs4bTNXWFhMcm56QW9GaHJRZGxCYTFRNjFJMlVxYnF4YkEwZFM5TGRPdDUrbkZGVlptK0U3QUFlVnlyOFVqVldUZEpRdlROM3VxMFZrTDBuMnBxMDMrSGI0Z1BSOHZycEQ3OUp5bHlVY0lSMFFOSWdNdEVGZTRlRkoraUM5K21iZU9qekhRa2w4Wkc1NTFYMkt5NnNsM09PbmY5M1hlZFFEMHZHMHJDWXBSR1orNTBrMDVqbHVLelJqY2lxQUNnTEhDRlNwY0x5QlNLZ3JYY0EwcWxwWURUSWJleDg5VHZSR1kxbm93ckM1bG1HTlQ4akpyeENZT1lEQWdNQkFBR2pZekJoTUE4R0ExVWRFd0VCL3dRRk1BTUJBZjh3SHdZRFZSMGpCQmd3Rm9BVWdoT2hvd0tVem1JTjRBYTJOMVpCY0Z4RnJpc3dIUVlEVlIwT0JCWUVGSUlUb2FNQ2xNNWlEZUFHdGpkV1FYQmNSYTRyTUE0R0ExVWREd0VCL3dRRUF3SUJoakFOQmdrcWhraUc5dzBCQVEwRkFBT0NBZ0VBSkdRS3JaMlUzSi9TcEdoUDd6V2p2d2VCWHhqVzV1U2R4MFY3bXd2NG12QzJWbEMxVHZ4RW41eVZuZEVVQ3BsR3AvbTBTM0EwN0J0UFoyNFpTdVJ3K21JcHRCbUNoYm5VMXZqMkJGcEZGVGhwc1FKRzBrRGpEMjNIbzZwM1J0TXJpYjhJaTBSbm9VYndwUDVOMkxpZU9idW9kOU9TOXEzTWdDbGh5OUY5OW1PV3ZEL3E1dkNWbyt1TFdadVE0YWN1VFROeGE1REh5aWpnQitHR28yT2hIbGRyU3BwK0xSZ1U1ZmtOS0cwTHpobElFR2RFQmFsMHB1Wi8rUXF0U3JyTERNVDRYUEtXTUo2Z3BzcjNsWGZiYTBFbDdiYi83NTZ0TVlBYlh6bW5ra1VxZGlPSTU3clZERlQ5Rkp4alZnbzVvVzhYT0tHU0xxTUgzMVhpSkNOb0g1ckpZOFZRM1ptTVN1aDk3a0FBaFh1RkliUVo3RnJrRjJ5K0dzS3BiMGE5WlVxRkJySmx6SHhDS2w4U1NUd2ZHRGdjcGVQWnhVSUlnUFBjSTRvWHdSb0IwSGJ0NTRJclJvRzdrV2s2OGdYMmNqS1YwWXRIbVZoRUVGcjNkaVpmTzdtQVRBNTRzTFpYOW4xbG9zbmY5eHJlRXpkRVlXYnlHVGhVd2wzM01QNlhMYUZSUGRiblFzaGJyb2VwemcrbmtzVTVWVksyWlpGSVdWWTZnK1JoSUNYVmRocWtCcE5tK2VLMCt3VUNBMXRYWXlSS29TVVZwTUZTQVpobnN5VWVaemFtUEhEZTRHa1RhbU1LNHFmWEtRT2I3RXRXVVdoNWZvVlN6YXF5dkZwcFU0Vk1wL2dLclBZSEQ2YldySEo1dkMvQjdXci9hUHRoTmtnWEZNR01yUjA9Il0sInR5cCI6Impvc2UiLCJzaWdUIjoiMjAyNC0wOS0xN1QxMjoyMTozMloiLCJjcml0IjpbInNpZ1QiXX0.eyJzdWIiOiJkaWQ6a2V5OnpEbmFlVjJuOW5LOFVhYnZjZ2FhOVhkSmtkYnFVYWhMTHBidDRXcVM4M0Y4cFBDdjciLCJuYmYiOjE3MjY1NzU2MDgsImlzcyI6ImRpZDplbHNpOlZBVEVTLVEwMDAwMDAwSiIsImV4cCI6MTcyOTE2NzYwOCwiaWF0IjoxNzI2NTc1NjA4LCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJodHRwczovL2RvbWUtbWFya2V0cGxhY2UuZXUvMjAyMi9jcmVkZW50aWFscy9sZWFyY3JlZGVudGlhbC92MSJdLCJpZCI6ImE5NmY0ZjA0LTI1OGYtNDM2Ny04YTIwLWQyOTk4ZTljYzc1OSIsInR5cGUiOlsiTEVBUkNyZWRlbnRpYWxFbXBsb3llZSIsIlZlcmlmaWFibGVDcmVkZW50aWFsIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7Im1hbmRhdGUiOnsiaWQiOiJjMjk2NTA1OS1jMTkyLTRlMzYtOTU0NS02ZTY1OWViNTdhYTgiLCJsaWZlX3NwYW4iOnsiZW5kX2RhdGVfdGltZSI6IjIwMjQtMTAtMTdUMTI6MjA6MDguNDA4NTE3MDg0WiIsInN0YXJ0X2RhdGVfdGltZSI6IjIwMjQtMDktMTdUMTI6MjA6MDguNDA4NTE3MDg0WiJ9LCJtYW5kYXRlZSI6eyJpZCI6ImRpZDprZXk6ekRuYWVWMm45bks4VWFidmNnYWE5WGRKa2RicVVhaExMcGJ0NFdxUzgzRjhwUEN2NyIsImVtYWlsIjoicnViZW4ubW9kYW1pb0BpbjIuZXMiLCJmaXJzdF9uYW1lIjoiUnViZW4iLCJsYXN0X25hbWUiOiJNb2RhbWlvIEdhcmNpYSIsIm1vYmlsZV9waG9uZSI6IiszNCA2NDAwOTk5OTkifSwibWFuZGF0b3IiOnsiY29tbW9uTmFtZSI6IlpFVVMgT0xJTVBPUyIsImNvdW50cnkiOiJFUyIsImVtYWlsQWRkcmVzcyI6ImRvbWVzdXBwb3J0QGluMi5lcyIsIm9yZ2FuaXphdGlvbiI6IklOMiIsIm9yZ2FuaXphdGlvbklkZW50aWZpZXIiOiJWQVRFUy1RMDAwMDAwMEoiLCJzZXJpYWxOdW1iZXIiOiJJRENFVS05OTk5OTk5OVAifSwicG93ZXIiOlt7ImlkIjoiM2E3YmMwMDEtMGNkNi00MWNjLTk2YmQtNjUwNzQ1ZjNjMWM4IiwidG1mX2FjdGlvbiI6IkV4ZWN1dGUiLCJ0bWZfZG9tYWluIjpudWxsLCJ0bWZfZnVuY3Rpb24iOiJPbmJvYXJkaW5nIiwidG1mX3R5cGUiOiJEb21haW4ifSx7ImlkIjoiYjE4N2JmMjgtZmRhMC00OTRiLWE1YjYtNzQ5MzNjNGUwOTUwIiwidG1mX2FjdGlvbiI6WyJDcmVhdGUiLCJVcGRhdGUiXSwidG1mX2RvbWFpbiI6bnVsbCwidG1mX2Z1bmN0aW9uIjoiUHJvZHVjdE9mZmVyaW5nIiwidG1mX3R5cGUiOiJEb21haW4ifSx7ImlkIjoiY2FmNWJhNTMtMWM2My00ZjE2LTgwMjUtZjVmOWE2NjFkYjk0IiwidG1mX2FjdGlvbiI6WyJQcm92aWRlciJdLCJ0bWZfZG9tYWluIjpudWxsLCJ0bWZfZnVuY3Rpb24iOiJEb21lUGxhdGZvcm0iLCJ0bWZfdHlwZSI6IkRvbWFpbiJ9XSwic2lnbmVyIjp7ImNvbW1vbk5hbWUiOiJaRVVTIE9MSU1QT1MiLCJjb3VudHJ5IjoiRVUiLCJlbWFpbEFkZHJlc3MiOiJkb21lc3VwcG9ydEBpbjIuZXMiLCJvcmdhbml6YXRpb24iOiJPTElNUE8iLCJvcmdhbml6YXRpb25JZGVudGlmaWVyIjoiVkFURVUtQjk5OTk5OTk5Iiwic2VyaWFsTnVtYmVyIjoiSURDRVUtOTk5OTk5OTlQIn19fSwiZXhwaXJhdGlvbkRhdGUiOiIyMDI0LTEwLTE3VDEyOjIwOjA4LjQwODUxNzA4NFoiLCJpc3N1YW5jZURhdGUiOiIyMDI0LTA5LTE3VDEyOjIwOjA4LjQwODUxNzA4NFoiLCJpc3N1ZXIiOiJkaWQ6ZWxzaTpWQVRFUy1RMDAwMDAwMEoiLCJ2YWxpZEZyb20iOiIyMDI0LTA5LTE3VDEyOjIwOjA4LjQwODUxNzA4NFoifSwianRpIjoiNjM0MzA0ODMtZjA4ZC00NmZmLTkwMzYtYWY3OWEwNDgwOGY1In0.ZKMMS01IbPpo1BPLQCYphb93GJiMJ3f7A7W4Ho8ISaCkxhNJl9b0K_HqPFHtq4jQkPk67H6yhztXyf1mqj8RYiiCwZzhjlJlEC0fj-FPzr7DTtD0Wgm7JlgyZ6uQ5MeJGBNOqxgCnmF6KWRzeACu8e0yu_I33-N2UmxswIKGj-RCGA-Ii5OJl2huPnF7TY2ioUIxQbWbOKlaXRGQQCsIVaNzwXBg51EM4GIpr5Ej1WI5gxTUoDcBBVGyk8NzVyGbuj9QfdzZ7XjV4Yw4KSMvh_AQ837VUBLZoD5a3wrogJevJ1pgyjmNHO5JhWiun1ObFM2odVY8T9cYU33AlSxYzvBYcnxGy7uUCXqp-P21Hip1aOzYy6BreryGW8iM1jSLVxdYPkwAsq4gYPCxwo_gK0yAfVg_AlR5OMJJ0h34wmd78F1W0I4KdJ0tHQX5c-2N2RRA1q4x2FZhunh9_Nug1vii1dR_kChJZy1Mik_hjYewjm1SswcTM1NvUdV1b20zRJrMnv2Sx7HRTCct0bw9uXWiMMtGCzXfcuk3AyRDVwkqnPoRN0EDghMu7wtsC7TNTP98KgkJiLEtN9HulNFkPvgYTRltABA3phGN8vUen_sSCHUpS9LG-24aKnTw8STCvnK9GV197irPWdLLcLTI8zkA5T3vyBN1pmSSSxNnQJY"
                )
        );

        ECKey ecKey = generateECKeyAndDidKey();
        String didKey = getDidKeyFromPublicKey(ecKey.toECPublicKey());
        System.out.println("Private Key - d: " + ecKey.getD() + " x: " + ecKey.getX() + " y: " + ecKey.getY());
        // Generate a JWT to test M2M
        ECKey ecPublicJWK = ecKey.toPublicJWK();
        JWSSigner signer = new ECDSASigner(ecKey);
        Payload payload = new Payload(Map.of(
                "iss", didKey,
                "iat", 1725951134,
                "exp", 1760079134,
                "aud", "http://localhost:9000",
                "sub", didKey,
                "vp", vp,
                "jti", "6bede557-46d3-4a6a-837d-2080e4c38222"
        ));
        JWSObject jwsObject = new JWSObject(
                new JWSHeader.Builder(JWSAlgorithm.ES256)
                        .type(JOSEObjectType.JWT)
                        //.keyID(ecKey.getKeyID() + "#" + ecKey.getKeyID().replace("did:key:","")).build(),
                        .keyID(ecKey.getKeyID()).build(),
                payload);
        // Compute the EC signature
        jwsObject.sign(signer);
        // Serialize the JWS to compact form
        String jwtBearer = jwsObject.serialize();
        System.out.println("JWT: " + jwtBearer);
        // The recipient creates a verifier with the public EC key
        JWSVerifier verifier = new ECDSAVerifier(ecPublicJWK);
        // Verify the EC signature
        assertTrue("ES256 signature verified", jwsObject.verify(verifier));
        assertEquals(payload.toString(), jwsObject.getPayload().toString());

    }

    private ECKey generateECKeyAndDidKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        // Generate a new key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(256);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        // Get Private and Public Key
        ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
        ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
        // Build did:key from KeyPair
        byte[] encodedKey = publicKey.getEncoded();
        KeyFactory keyFactory = KeyFactory.getInstance("EC", BouncyCastleProviderSingleton.getInstance());
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedKey);
        BCECPublicKey bcPublicKey = (BCECPublicKey) keyFactory.generatePublic(keySpec);
        byte[] pubKeyBytes = bcPublicKey.getQ().getEncoded(true);
        int multiCodecKeyCodeForSecp256r1 = 0x1200;
        UVarInt codeVarInt = new UVarInt(multiCodecKeyCodeForSecp256r1);
        int totalLength = pubKeyBytes.length + codeVarInt.getLength();
        byte[] multicodecAndRawKey = new byte[totalLength];
        System.arraycopy(codeVarInt.getBytes(), 0, multicodecAndRawKey, 0, codeVarInt.getLength());
        System.arraycopy(pubKeyBytes, 0, multicodecAndRawKey, codeVarInt.getLength(), pubKeyBytes.length);
        String multiBase58Btc = Base58.encode(multicodecAndRawKey);
        String didKey = "did:key:z" + multiBase58Btc;
        System.out.println("DID Key: " + didKey);
        return new ECKey.Builder(Curve.P_256, publicKey)
                .privateKey(privateKey)
                .keyID(didKey)
                .build();
    }

    private String getDidKeyFromPublicKey(ECPublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] encodedKey = publicKey.getEncoded();
        KeyFactory keyFactory = KeyFactory.getInstance("EC", BouncyCastleProviderSingleton.getInstance());
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedKey);
        BCECPublicKey bcPublicKey = (BCECPublicKey) keyFactory.generatePublic(keySpec);
        byte[] pubKeyBytes = bcPublicKey.getQ().getEncoded(true);
        int multiCodecKeyCodeForSecp256r1 = 0x1200;
        UVarInt codeVarInt = new UVarInt(multiCodecKeyCodeForSecp256r1);
        int totalLength = pubKeyBytes.length + codeVarInt.getLength();
        byte[] multicodecAndRawKey = new byte[totalLength];
        System.arraycopy(codeVarInt.getBytes(), 0, multicodecAndRawKey, 0, codeVarInt.getLength());
        System.arraycopy(pubKeyBytes, 0, multicodecAndRawKey, codeVarInt.getLength(), pubKeyBytes.length);
        String multiBase58Btc = Base58.encode(multicodecAndRawKey);
        return "did:key:z" + multiBase58Btc;
    }

    @Test
    void verifyJWTSignature() {
        String jwt = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImRpZDprZXk6ekRuYWVmd01iRU50cENvQ0NkWWdGTEtKQ3VWdGtHWjhQaEVnN2dXQVlCZWVLQXl1eSJ9.eyJpc3MiOiJkaWQ6a2V5OnpEbmFlZndNYkVOdHBDb0NDZFlnRkxLSkN1VnRrR1o4UGhFZzdnV0FZQmVlS0F5dXkiLCJhdWQiOiJodHRwczovL3ZlcmlmaWVyLmNvbSIsInJlc3BvbnNlX3R5cGUiOiJjb2RlIiwiY2xpZW50X2lkIjoiZGlkOmtleTp6RG5hZWZ3TWJFTnRwQ29DQ2RZZ0ZMS0pDdVZ0a0daOFBoRWc3Z1dBWUJlZUtBeXV5IiwicmVkaXJlY3RfdXJpIjoiaHR0cHM6Ly9yZWRpcmVjdC5jb20iLCJzY29wZSI6Im9wZW5pZCBsZWFyY3JlZCIsImlhdCI6MTcyNzk1NzE3OH0.0mluetH1W6-7mZYbY4ZncSuDEA7HsFbIoOVOVM2kwHzhHTbWwcgontLktnQDu6SUcc938R77G1au90mD8lax-w";
        byte[] publicKeyBytes = getPublicKeyBytesFromDid("did:key:zDnaefwMbENtpCoCCdYgFLKJCuVtkGZ8PhEg7gWAYBeeKAyuy");
        try {
            // Set the curve as secp256r1
            ECCurve curve = new SecP256R1Curve();
            BigInteger x = new BigInteger(1, Arrays.copyOfRange(publicKeyBytes, 1, publicKeyBytes.length));
            // Recover the Y coordinate from the X coordinate and the curve
            BigInteger y = curve.decodePoint(publicKeyBytes).getYCoord().toBigInteger();
            ECPoint point = new ECPoint(x, y);
            // Fetch the ECParameterSpec for secp256r1
            ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
            ECNamedCurveSpec params = new ECNamedCurveSpec("secp256r1", ecSpec.getCurve(), ecSpec.getG(), ecSpec.getN());
            // Create a KeyFactory and generate the public key
            KeyFactory kf = KeyFactory.getInstance("EC");
            java.security.spec.ECPublicKeySpec pubKeySpec = new java.security.spec.ECPublicKeySpec(point, params);
            PublicKey publicKey = kf.generatePublic(pubKeySpec);
            // Parse the JWT and create a verifier
            SignedJWT signedJWT = SignedJWT.parse(jwt);
            ECDSAVerifier verifier = new ECDSAVerifier((ECPublicKey) publicKey);
            // Verify the signature
            if (!signedJWT.verify(verifier)) {
                throw new JWTVerificationException("Invalid JWT signature");
            }
        } catch (Exception e) {
            throw new RuntimeException("JWT signature verification failed.", e);
        }
    }


    public byte[] getPublicKeyBytesFromDid(String did) {
        if (!did.startsWith("did:key:")) {
            throw new IllegalArgumentException("Unsupported DID type. Only did:key is supported for the moment.");
        }
        // Remove the "did:key:" prefix to get the actual encoded public key
        String encodedPublicKey = did.substring("did:key:".length());
        // Decode the public key from its encoded representation
        return decodePublicKeyIntoBytes(encodedPublicKey);
    }

    private byte[] decodePublicKeyIntoBytes(String publicKey) {
        // Remove the prefix "z" to get the multibase encoded string
        if (!publicKey.startsWith("z")) {
            throw new IllegalArgumentException("Invalid Public Key.");
        }
        String multibaseEncoded = publicKey.substring(1);
        // Multibase decode (Base58) the encoded part to get the bytes
        byte[] decodedBytes = io.github.novacrypto.base58.Base58.base58Decode(multibaseEncoded);
        // Multicodec prefix is fixed for "0x1200" for the secp256r1 curve
        int prefixLength = 2;
        // Extract public key bytes after the multicodec prefix
        byte[] publicKeyBytes = new byte[decodedBytes.length - prefixLength];
        System.arraycopy(decodedBytes, prefixLength, publicKeyBytes, 0, publicKeyBytes.length);
        return publicKeyBytes;
    }

    @Test
    void generateCodeChallenge() throws NoSuchAlgorithmException {
        String codeVerifier = "hola123";
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
        System.out.println(Base64.getUrlEncoder().withoutPadding().encodeToString(digest));
    }

    @Test
    void generateTokenTest() throws NoSuchAlgorithmException, InvalidKeySpecException, JOSEException {
        ECKey ecKey = generateECKeyAndDidKey();
        System.out.println("Private Key - d: " + ecKey.getD() + " x: " + ecKey.getX() + " y: " + ecKey.getY());
        String didKey = getDidKeyFromPublicKey(ecKey.toECPublicKey());
        // Generate a JWT to test M2M
        ECKey ecPublicJWK = ecKey.toPublicJWK();
        JWSSigner signer = new ECDSASigner(ecKey);
        Payload payload = new Payload(Map.of(
                "iss", didKey,
                "iat", 1725951134,
                "exp", 1760079134,
                "sub", didKey
        ));
        JWSObject jwsObject = new JWSObject(
                new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(ecKey.getKeyID()).build(),
                payload);
        // Compute the EC signature
        jwsObject.sign(signer);
        // Serialize the JWS to compact form
        String jwtBearer = jwsObject.serialize();
        System.out.println("JWT: " + jwtBearer);
        // The recipient creates a verifier with the public EC key
        JWSVerifier verifier = new ECDSAVerifier(ecPublicJWK);
        // Verify the EC signature
        assertTrue("ES256 signature verified", jwsObject.verify(verifier));
        assertEquals(payload.toString(), jwsObject.getPayload().toString());
    }

}