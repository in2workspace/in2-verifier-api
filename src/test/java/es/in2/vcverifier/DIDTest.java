package es.in2.vcverifier;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.exception.JWTVerificationException;
import es.in2.vcverifier.util.UVarInt;
import org.bitcoinj.base.Base58;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.*;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.util.AssertionErrors.assertTrue;

class DIDTest {

    // https://www.scottbrady91.com/tools/jwt

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
    void generateJWT() throws NoSuchAlgorithmException, InvalidKeySpecException, JOSEException {
        Map<String, Object> vp = Map.of(
                "@context", List.of("https://www.w3.org/2018/credentials/v1"),
                "holder", "did:key:zDnaepbQkLnywX4GHsnpTuGQkBHtJ4UnGM97ts7XuM273L1ih",
                "id", "urn:uuid:41acada3-67b4-494e-a6e3-e0966449f25d",
                "type", List.of("VerifiablePresentation"),
                "verifiableCredential", List.of(
                        "eyJhbGciOiJSUzI1NiIsImN0eSI6Impzb24iLCJraWQiOiJNSUhRTUlHM3BJRzBNSUd4TVNJd0lBWURWUVFEREJsRVNVZEpWRVZNSUZSVElFRkVWa0ZPUTBWRUlFTkJJRWN4TVJJd0VBWURWUVFGRXdsQ05EYzBORGMxTmpBeEt6QXBCZ05WQkFzTUlrUkpSMGxVUlV3Z1ZGTWdRMFZTVkVsR1NVTkJWRWxQVGlCQlZWUklUMUpKVkZreEtEQW1CZ05WQkFvTUgwUkpSMGxVUlV3Z1QwNGdWRkpWVTFSRlJDQlRSVkpXU1VORlV5QlRURlV4RXpBUkJnTlZCQWNNQ2xaaGJHeGhaRzlzYVdReEN6QUpCZ05WQkFZVEFrVlRBaFExL3pkM2dseTl4S2dRVFE3bDNXOERnRUZTcXc9PSIsIng1dCNTMjU2IjoiNWcyVHBXS3pvelFrT201bFFuZk50cWxSS3MteW80aWNqWkVhYWVJTUtsMCIsIng1YyI6WyJNSUlHT3pDQ0JTT2dBd0lCQWdJVU5mODNkNEpjdmNTb0VFME81ZDF2QTRCQlVxc3dEUVlKS29aSWh2Y05BUUVOQlFBd2diRXhJakFnQmdOVkJBTU1HVVJKUjBsVVJVd2dWRk1nUVVSV1FVNURSVVFnUTBFZ1J6RXhFakFRQmdOVkJBVVRDVUkwTnpRME56VTJNREVyTUNrR0ExVUVDd3dpUkVsSFNWUkZUQ0JVVXlCRFJWSlVTVVpKUTBGVVNVOU9JRUZWVkVoUFVrbFVXVEVvTUNZR0ExVUVDZ3dmUkVsSFNWUkZUQ0JQVGlCVVVsVlRWRVZFSUZORlVsWkpRMFZUSUZOTVZURVRNQkVHQTFVRUJ3d0tWbUZzYkdGa2IyeHBaREVMTUFrR0ExVUVCaE1DUlZNd0hoY05NalF3TlRJeE1Ea3pNVEF6V2hjTk1qY3dOVEl4TURrek1UQXlXakNCdXpFZE1Cc0dBMVVFQXd3VU5UWTFOalUyTlRaUUlFcGxjM1Z6SUZKMWFYb3hHREFXQmdOVkJBVVREMGxFUTBWVExUVTJOVFkxTmpVMlVERU9NQXdHQTFVRUtnd0ZTa1ZUVlZNeERUQUxCZ05WQkFRTUJGSlZTVm94SHpBZEJnTlZCQXNNRmtSUFRVVWdRM0psWkdWdWRHbGhiQ0JKYzNOMVpYSXhHREFXQmdOVkJHRU1EMVpCVkVWVExWRXdNREF3TURBd1NqRVpNQmNHQTFVRUNnd1FSRTlOUlNCTllYSnJaWFJ3YkdGalpURUxNQWtHQTFVRUJoTUNSVk13Z2dJaU1BMEdDU3FHU0liM0RRRUJBUVVBQTRJQ0R3QXdnZ0lLQW9JQ0FRRFp4OVZGVHFIYVVBVlRFWGg1c0w1R3ZvcHZCR1M0azVkZ2YrdGJCRlB1M285Ky8vSmMvSkRHUzZSazZDM2ZjNksveWhmUEJDUXdETXdlYkc2QVpBbVUzTDhYMWVsbHZBRW5ZQjJwd1NhdmdicHFLMkRab3dUdGliM0hYU0FHK1dBTzJQc040YVlUSHF0Tks4Z1pybFVFNlg5ZG16aFRSQUlxc0x5MXZDQXZuV0xpQjUzdSsvdW5JMk41SWpmV1RYdStvMU94b1UrOXZneHg1VWd6d2ZaVU5iaUxkWUJaQ1M3NUpGdW9BVFVZekRRbmcvU3kvNXMvQ3YwZlVySlR1MUo2Y3UyUDJ3LzV5MmRHR0w0MlBRRWVnYXlZbS82WThBYjRoczFFU1krOUxDSmdTMnI2QTNYbFNIbWxObmNVd1V3VmRMTlB1MGx2NEFrTUtvRHMwdHBOWm1lMmN2NGd4a05tVFk5cjV0aEdOTHpCcVFjS1NoNVdUK01RTGV0Tmllcko0aXBRUXgxSHhNNEZRSXBrbncwSXo4ZTdRZitMT2FMNkZBYlF2WDVEUDF2QmlxUXJ2TExHeisrMDRGZ0lVeDJZVlVMZWF0MDdOMGRldWhrbytRTjZ3S2gyMDh6ZmpwQVVKTDRVWENmMFphU29SRmFweCtSUFFCZjlOdGpTeEc3VktNK3NQNjZpcFhQNWl4dFhCa3FOOEVYYnVOVUdXa2FHc01MVmo4VHFsZ3p6djFwYXRlbElHeFlHUHV6ejMzcy94T09nTDdzN0g3S2tNbDBvd2ZDcVZGTEVYS1RjOEFPSGhoNFZtNitjdUpYQnhSU2FJZjdVWVhLbkhoYVQwSzVrM3ZuSHorL0RIY1hIWGo1UzdPRnVCVkoyWitPMWFTMzdoYys3ZXplZWFRSURBUUFCbzRJQlBUQ0NBVGt3REFZRFZSMFRBUUgvQkFJd0FEQWZCZ05WSFNNRUdEQVdnQlFTUzAzRWkvSVcwZ3R6aVJCS3hUMEUyOGxDdlRCc0JnZ3JCZ0VGQlFjQkFRUmdNRjR3TmdZSUt3WUJCUVVITUFLR0ttaDBkSEE2THk5d2Eya3VaR2xuYVhSbGJIUnpMbVZ6TDBSSlIwbFVSVXhVVTBGRVZrY3hMbU55ZERBa0JnZ3JCZ0VGQlFjd0FZWVlhSFIwY0RvdkwyOWpjM0F1WkdsbmFYUmxiSFJ6TG1Wek1BOEdDU3NHQVFVRkJ6QUJCUVFDQlFBd0hRWURWUjBsQkJZd0ZBWUlLd1lCQlFVSEF3SUdDQ3NHQVFVRkJ3TUVNRHNHQTFVZEh3UTBNREl3TUtBdW9DeUdLbWgwZEhBNkx5OWpjbXd1Y0d0cExtUnBaMmwwWld4MGN5NWxjeTlFVkZOQlpIWkRRVWN4TG1OeWJEQWRCZ05WSFE0RUZnUVVKRHZTdXJIRGZ4TitOaW85TFBGQkprUkNMbzh3RGdZRFZSMFBBUUgvQkFRREFnYkFNQTBHQ1NxR1NJYjNEUUVCRFFVQUE0SUJBUUFaRDlNWVZLZW83TDNzbkd6TFBGTDZpWHNhZUVOUURNb1BmSXBOSGMvM3JMRVdYYkN3RzNDQ3hzbFVqUmkwcG1JUkF4T2x6L1RPMnc1MFk5WGtHanU4dHh5dENyTjUyZ3pRb0d6dkZKYXA0R0QrYzVNNFZ3UWY1Z2hEeVFGWVRpU1pBMVR6aUlLbjhLUjVBZmtkeWRDRUlQUjE4Tjl5cEQzeFE1SU05aU94dGpGQWVuU2oxWHdXT2E0bHhUUURvRDFhNi9HcVNkTE12Y2EySll2cTFpNXFSdS9lcjR2TlFYa05TemlaTHFvVUdscGNnc2VtMTRvV3NTZDZhYmxaZkxMbGQvUnRFdXRHOUhaaStkRW5uZ21CUzNXMi9VMEx1ZmZ0UDZHMndFYVNpd0VPZ1FnUGREdWtmL1lVb3FweFY1a3FqRnJjN0tKdDBxVmp5OHlMTFNhRSJdLCJzaWdUIjoiMjAyNC0wNi0xMFQwOToyOToxM1oiLCJjcml0IjpbInNpZ1QiXX0.eyJzdWIiOiJkaWQ6a2V5OnpEbmFlcGJRa0xueXdYNEdIc25wVHVHUWtCSHRKNFVuR005N3RzN1h1TTI3M0wxaWgiLCJuYmYiOjE3MTc0MzgwMDMsImlzcyI6ImRpZDplbHNpOlZBVEVTLUI2MDY0NTkwMCIsImV4cCI6MTcyMDAzMDAwMywiaWF0IjoxNzE3NDM4MDAzLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJodHRwczovL3d3dy5ldmlkZW5jZWxlZGdlci5ldS8yMDIyL2NyZWRlbnRpYWxzL2VtcGxveWVlL3YxIl0sImlkIjoiOGM3YTYyMTMtNTQ0ZC00NTBkLThlM2QtYjQxZmE5MDA5MTk4IiwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIkxFQVJDcmVkZW50aWFsRW1wbG95ZWUiXSwiaXNzdWVyIjp7ImlkIjoiZGlkOmVsc2k6VkFURVMtQjYwNjQ1OTAwIn0sImlzc3VhbmNlRGF0ZSI6IjIwMjQtMDUtMTMgMDU6MjA6MzMuNjEyMTg4Nzk3ICswMDAwIFVUQyIsInZhbGlkRnJvbSI6IjIwMjQtMDUtMTMgMDU6MjA6MzMuNjEyMTg4Nzk3ICswMDAwIFVUQyIsImV4cGlyYXRpb25EYXRlIjoiMjAyNS0wNS0xMyAwNToyMDozMy42MTIxODg3OTcgKzAwMDAgVVRDIiwiY3JlZGVudGlhbFN1YmplY3QiOnsibWFuZGF0ZSI6eyJpZCI6IjdiZjU1ZDJlLTUyNDctNDcxNC05MWQxLThlMmY4Y2I3MzBkMSIsImxpZmVfc3BhbiI6eyJlbmRfZGF0ZV90aW1lIjoiMjAyNC0wNi0yOVQwNzo0NzozOC41OTYxNDU0NTlaIiwic3RhcnRfZGF0ZV90aW1lIjoiMjAyNC0wNS0zMFQwNzo0NzozOC41OTYxNDU0NTlaIn0sIm1hbmRhdGVlIjp7ImlkIjoiZGlkOmtleTp6RG5hZXBiUWtMbnl3WDRHSHNucFR1R1FrQkh0SjRVbkdNOTd0czdYdU0yNzNMMWloIiwiZW1haWwiOiJydWJlbi5tb2RhbWlvQGluMi5lcyIsImZpcnN0X25hbWUiOiJSdWJlbiIsImxhc3RfbmFtZSI6Ik1vZGFtaW8iLCJtb2JpbGVfcGhvbmUiOiIrMzQgNjk5OTk5OTk5In0sIm1hbmRhdG9yIjp7ImNvbW1vbk5hbWUiOiJJTjIiLCJjb3VudHJ5IjoiRVMiLCJlbWFpbEFkZHJlc3MiOiJycmhoQGluMi5lcyIsIm9yZ2FuaXphdGlvbiI6IklOMiwgSW5nZW5pZXLDrWEgZGUgbGEgSW5mb3JtYWNpw7NuLCBTLkwuIiwib3JnYW5pemF0aW9uSWRlbnRpZmllciI6IlZBVEVTLUI2MDY0NTkwMCIsInNlcmlhbE51bWJlciI6IkI2MDY0NTkwMCJ9LCJwb3dlciI6W3siaWQiOiJmMGQxMzNmZS0yYjJlLTRmZWEtOWQ1OC04NmIyYzRmYWFhOTkiLCJ0bWZfYWN0aW9uIjoiRXhlY3V0ZSIsInRtZl9mdW5jdGlvbiI6Ik9uYm9hcmRpbmciLCJ0bWZfdHlwZSI6IkRvbWFpbiJ9LHsiaWQiOiJhODRmODlkYS1iYWI2LTRmZDQtOGI4YS05NDhiMDllNDkwODEiLCJ0bWZfYWN0aW9uIjpbIk9wZXJhdG9yIiwiTWFya2V0cGxhY2UiXSwidG1mX2Z1bmN0aW9uIjoiRG9tZVBsYXRmb3JtIiwidG1mX3R5cGUiOiJEb21haW4ifV0sInNpZ25lciI6eyJjb21tb25OYW1lIjoiSU4yIiwiY291bnRyeSI6IkVTIiwiZW1haWxBZGRyZXNzIjoicnJoaEBpbjIuZXMiLCJvcmdhbml6YXRpb24iOiJJTjIsIEluZ2VuaWVyw61hIGRlIGxhIEluZm9ybWFjacOzbiwgUy5MLiIsIm9yZ2FuaXphdGlvbklkZW50aWZpZXIiOiJWQVRFUy1CNjA2NDU5MDAiLCJzZXJpYWxOdW1iZXIiOiJCNjA2NDU5MDAifX19fSwianRpIjoiNzQ1OTM5YzAtNGRiZi00NTFiLWEyMTMtMzJkZjRmMDdjMjY0In0.D8LMAWxnJKw99fiwjrPvjHJqQFs5-de42Yrvi-PkG7AJ3UUL2m3Vhmb732ufVS-T8xHqrRKYLrFqTUilbjOTi8y48HgZvFLRsKivnRvr6Gb23D9x2RqTIHKWR5ceLcfzwXYl3ulOKJD5Dq9x4ZI6KL0DIhlu3og9tYj62hOfJjcpgxRUY2KTyeK9PLFIN-Bv4RWA0otD6AnDIv5J3WH9ZgC6LWb_-WfoBFRFYYVsPXnkz2_e7wd2ylTh6q5mUFr8RjJ5eZaMDwa0nn5QaQZRxOlMPQsj8zAHhTVZuaRzDYqB9ADWdmTKqbvZa1pCewyR5BC_-DMJFqGGIHG9YBHV665Qz-y0zWEj_yUrgTyIFv9PJS7hdYXufvIVuK6fGe5HG2k1HqIiEnhJhAKAkskQYbpSBpcQUsCwJbaBnyV6pI2xYv9r3SJH_64o5xT3aumnkcp3kvFqxz0e8dIH6FJbv8PfEwEwZYXLxz3GZZopTIbiFwYc7bvRU9nYm96okj8auPhf_camghG58UIsEXg-Nr-bxi-M3pK5NF-wwN6DXyHN5eQAHl0vq0PKqUaIb8lIW4Cns_4tBqHpqYhDSLcCf7OJocgVrk660S0ok18r3yu4S39d5xVEBO1y7o5eUCNZDjllvwh0kjkgm63CIz-EqoSnxobTO79m3oRGCh3l37o"
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
        String jwt = """
                eyJraWQiOiJkaWQ6a2V5OnpEbmFlcGJRa0xueXdYNEdIc25wVHVHUWtCSHRKNFVuR005N3RzN1h1TTI3M0wxaWgjekRuYWVwYlFrT
                G55d1g0R0hzbnBUdUdRa0JIdEo0VW5HTTk3dHM3WHVNMjczTDFpaCIsInR5cCI6IkpXVCIsImFsZyI6IkVTMjU2In0.eyJzdWIiOi
                JkaWQ6a2V5OnpEbmFlcGJRa0xueXdYNEdIc25wVHVHUWtCSHRKNFVuR005N3RzN1h1TTI3M0wxaWgiLCJuYmYiOjE3MTgwMTU0NTY
                sImlzcyI6ImRpZDprZXk6ekRuYWVwYlFrTG55d1g0R0hzbnBUdUdRa0JIdEo0VW5HTTk3dHM3WHVNMjczTDFpaCIsInZwIjp7IkBj
                b250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sImhvbGRlciI6ImRpZDprZXk6ekRuYWVwY
                lFrTG55d1g0R0hzbnBUdUdRa0JIdEo0VW5HTTk3dHM3WHVNMjczTDFpaCIsImlkIjoidXJuOnV1aWQ6NDFhY2FkYTMtNjdiNC00OT
                RlLWE2ZTMtZTA5NjY0NDlmMjVkIiwidHlwZSI6WyJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIl0sInZlcmlmaWFibGVDcmVkZW50aWF
                sIjpbImV5SmhiR2NpT2lKU1V6STFOaUlzSW1OMGVTSTZJbXB6YjI0aUxDSnJhV1FpT2lKTlNVaFJUVWxITTNCSlJ6Qk5TVWQ0VFZO
                SmQwbEJXVVJXVVZGRVJFSnNSVk5WWkVwV1JWWk5TVVpTVkVsRlJrVldhMFpQVVRCV1JVbEZUa0pKUldONFRWSkpkMFZCV1VSV1VWR
                kdSWGRzUTA1RVl6Qk9SR014VG1wQmVFdDZRWEJDWjA1V1FrRnpUVWxyVWtwU01HeFZVbFYzWjFaR1RXZFJNRlpUVmtWc1IxTlZUa0
                pXUld4UVZHbENRbFpXVWtsVU1VcEtWa1pyZUV0RVFXMUNaMDVXUWtGdlRVZ3dVa3BTTUd4VlVsVjNaMVF3TkdkV1JrcFdWVEZTUmx
                KRFFsUlNWa3BYVTFWT1JsVjVRbFJVUmxWNFJYcEJVa0puVGxaQ1FXTk5RMnhhYUdKSGVHaGFSemx6WVZkUmVFTjZRVXBDWjA1V1Fr
                RlpWRUZyVmxSQmFGRXhMM3BrTTJkc2VUbDRTMmRSVkZFM2JETlhPRVJuUlVaVGNYYzlQU0lzSW5nMWRDTlRNalUySWpvaU5XY3lWS
                EJYUzNwdmVsRnJUMjAxYkZGdVprNTBjV3hTUzNNdGVXODBhV05xV2tWaFlXVkpUVXRzTUNJc0luZzFZeUk2V3lKTlNVbEhUM3BEUT
                BKVFQyZEJkMGxDUVdkSlZVNW1PRE5rTkVwamRtTlRiMFZGTUU4MVpERjJRVFJDUWxWeGMzZEVVVmxLUzI5YVNXaDJZMDVCVVVWT1F
                sRkJkMmRpUlhoSmFrRm5RbWRPVmtKQlRVMUhWVkpLVWpCc1ZWSlZkMmRXUmsxblVWVlNWMUZWTlVSU1ZWRm5VVEJGWjFKNlJYaEZh
                a0ZSUW1kT1ZrSkJWVlJEVlVrd1RucFJNRTU2VlRKTlJFVnlUVU5yUjBFeFZVVkRkM2RwVWtWc1NGTldVa1pVUTBKVlZYbENSRkpXU
                2xWVFZWcEtVVEJHVlZOVk9VOUpSVVpXVmtWb1VGVnJiRlZYVkVWdlRVTlpSMEV4VlVWRFozZG1Va1ZzU0ZOV1VrWlVRMEpRVkdsQ1
                ZWVnNWbFJXUlZaRlNVWk9SbFZzV2twUk1GWlVTVVpPVFZaVVJWUk5Ra1ZIUVRGVlJVSjNkMHRXYlVaellrZEdhMkl5ZUhCYVJFVk1
                UVUZyUjBFeFZVVkNhRTFEVWxaTmQwaG9ZMDVOYWxGM1RsUkplRTFFYTNwTlZFRjZWMmhqVGsxcVkzZE9WRWw0VFVScmVrMVVRWGxY
                YWtOQ2RYcEZaRTFDYzBkQk1WVkZRWGQzVlU1VVdURk9hbFV5VGxSYVVVbEZjR3hqTTFaNlNVWktNV0ZZYjNoSFJFRlhRbWRPVmtKQ
                lZWUkVNR3hGVVRCV1ZFeFVWVEpPVkZreFRtcFZNbFZFUlU5TlFYZEhRVEZWUlV0bmQwWlRhMVpVVmxaTmVFUlVRVXhDWjA1V1FrRl
                JUVUpHU2xaVFZtOTRTSHBCWkVKblRsWkNRWE5OUm10U1VGUlZWV2RSTTBwc1drZFdkV1JIYkdoaVEwSktZek5PTVZwWVNYaEhSRUZ
                YUW1kT1ZrSkhSVTFFTVZwQ1ZrVldWRXhXUlhkTlJFRjNUVVJCZDFOcVJWcE5RbU5IUVRGVlJVTm5kMUZTUlRsT1VsTkNUbGxZU25K
                YVdGSjNZa2RHYWxwVVJVeE5RV3RIUVRGVlJVSm9UVU5TVmsxM1oyZEphVTFCTUVkRFUzRkhVMGxpTTBSUlJVSkJVVlZCUVRSSlEwU
                jNRWGRuWjBsTFFXOUpRMEZSUkZwNE9WWkdWSEZJWVZWQlZsUkZXR2cxYzB3MVIzWnZjSFpDUjFNMGF6VmtaMllyZEdKQ1JsQjFNMj
                g1S3k4dlNtTXZTa1JIVXpaU2F6WkRNMlpqTmtzdmVXaG1VRUpEVVhkRVRYZGxZa2MyUVZwQmJWVXpURGhZTVdWc2JIWkJSVzVaUWp
                Kd2QxTmhkbWRpY0hGTE1rUmFiM2RVZEdsaU0waFlVMEZISzFkQlR6SlFjMDQwWVZsVVNIRjBUa3M0WjFweWJGVkZObGc1WkcxNmFG
                UlNRVWx4YzB4NU1YWkRRWFp1VjB4cFFqVXpkU3N2ZFc1Sk1rNDFTV3BtVjFSWWRTdHZNVTk0YjFVck9YWm5lSGcxVldkNmQyWmFWV
                TVpYVV4a1dVSmFRMU0zTlVwR2RXOUJWRlZaZWtSUmJtY3ZVM2t2TlhNdlEzWXdabFZ5U2xSMU1VbzJZM1V5VURKM0x6VjVNbVJIUj
                B3ME1sQlJSV1ZuWVhsWmJTODJXVGhCWWpSb2N6RkZVMWtyT1V4RFNtZFRNbkkyUVROWWJGTkliV3hPYm1OVmQxVjNWbVJNVGxCMU1
                HeDJORUZyVFV0dlJITXdkSEJPV20xbE1tTjJOR2Q0YTA1dFZGazVjalYwYUVkT1RIcENjVkZqUzFOb05WZFVLMDFSVEdWMFRtbGxj
                a28wYVhCUlVYZ3hTSGhOTkVaUlNYQnJibmN3U1hvNFpUZFJaaXRNVDJGTU5rWkJZbEYyV0RWRVVERjJRbWx4VVhKMlRFeEhlaXNyT
                URSR1owbFZlREpaVmxWTVpXRjBNRGRPTUdSbGRXaHJieXRSVGpaM1MyZ3lNRGg2Wm1wd1FWVktURFJWV0VObU1GcGhVMjlTUm1Gd2
                VDdFNVRkZDWmpsT2RHcFRlRWMzVmt0TkszTlFOalpwY0ZoUU5XbDRkRmhDYTNGT09FVllZblZPVlVkWGEyRkhjMDFNVm1vNFZIRnN
                aM3A2ZGpGd1lYUmxiRWxIZUZsSFVIVjZlak16Y3k5NFQwOW5URGR6TjBnM1MydE5iREJ2ZDJaRGNWWkdURVZZUzFSak9FRlBTR2hv
                TkZadE5pdGpkVXBZUW5oU1UyRkpaamRWV1ZoTGJraG9ZVlF3U3pWck0zWnVTSG9yTDBSSVkxaElXR28xVXpkUFJuVkNWa295V2l0U
                E1XRlRNemRvWXlzM1pYcGxaV0ZSU1VSQlVVRkNielJKUWxCVVEwTkJWR3QzUkVGWlJGWlNNRlJCVVVndlFrRkpkMEZFUVdaQ1owNV
                dTRk5OUlVkRVFWZG5RbEZUVXpBelJXa3ZTVmN3WjNSNmFWSkNTM2hVTUVVeU9HeERkbFJDYzBKblozSkNaMFZHUWxGalFrRlJVbWR
                OUmpSM1RtZFpTVXQzV1VKQ1VWVklUVUZMUjB0dGFEQmtTRUUyVEhrNWQyRXlhM1ZhUjJ4dVlWaFNiR0pJVW5wTWJWWjZUREJTU2xJ
                d2JGVlNWWGhWVlRCR1JWWnJZM2hNYlU1NVpFUkJhMEpuWjNKQ1owVkdRbEZqZDBGWldWbGhTRkl3WTBSdmRrd3lPV3BqTTBGMVdrZ
                HNibUZZVW14aVNGSjZURzFXZWsxQk9FZERVM05IUVZGVlJrSjZRVUpDVVZGRFFsRkJkMGhSV1VSV1VqQnNRa0paZDBaQldVbExkMW
                xDUWxGVlNFRjNTVWREUTNOSFFWRlZSa0ozVFVWTlJITkhRVEZWWkVoM1VUQk5SRWwzVFV0QmRXOURlVWRMYldnd1pFaEJOa3g1T1d
                wamJYZDFZMGQwY0V4dFVuQmFNbXd3V2xkNE1HTjVOV3hqZVRsRlZrWk9RbHBJV2tSUlZXTjRURzFPZVdKRVFXUkNaMDVXU0ZFMFJV
                Wm5VVlZLUkhaVGRYSklSR1o0VGl0T2FXODVURkJHUWtwclVrTk1iemgzUkdkWlJGWlNNRkJCVVVndlFrRlJSRUZuWWtGTlFUQkhRM
                U54UjFOSllqTkVVVVZDUkZGVlFVRTBTVUpCVVVGYVJEbE5XVlpMWlc4M1RETnpia2Q2VEZCR1REWnBXSE5oWlVWT1VVUk5iMUJtU1
                hCT1NHTXZNM0pNUlZkWVlrTjNSek5EUTNoemJGVnFVbWt3Y0cxSlVrRjRUMng2TDFSUE1uYzFNRms1V0d0SGFuVTRkSGg1ZEVOeVR
                qVXlaM3BSYjBkNmRrWktZWEEwUjBRcll6Vk5ORlozVVdZMVoyaEVlVkZHV1ZScFUxcEJNVlI2YVVsTGJqaExValZCWm10a2VXUkRS
                VWxRVWpFNFRqbDVjRVF6ZUZFMVNVMDVhVTk0ZEdwR1FXVnVVMm94V0hkWFQyRTBiSGhVVVVSdlJERmhOaTlIY1ZOa1RFMTJZMkV5U
                2xsMmNURnBOWEZTZFM5bGNqUjJUbEZZYTA1VGVtbGFUSEZ2VlVkc2NHTm5jMlZ0TVRSdlYzTlRaRFpoWW14YVpreE1iR1F2VW5SRm
                RYUkhPVWhhYVN0a1JXNXVaMjFDVXpOWE1pOVZNRXgxWm1aMFVEWkhNbmRGWVZOcGQwVlBaMUZuVUdSRWRXdG1MMWxWYjNGd2VGWTF
                hM0ZxUm5Kak4wdEtkREJ4Vm1wNU9IbE1URk5oUlNKZExDSnphV2RVSWpvaU1qQXlOQzB3TmkweE1GUXdPVG95T1RveE0xb2lMQ0pq
                Y21sMElqcGJJbk5wWjFRaVhYMC5leUp6ZFdJaU9pSmthV1E2YTJWNU9ucEVibUZsY0dKUmEweHVlWGRZTkVkSWMyNXdWSFZIVVd0Q
                1NIUktORlZ1UjAwNU4zUnpOMWgxVFRJM00wd3hhV2dpTENKdVltWWlPakUzTVRjME16Z3dNRE1zSW1semN5STZJbVJwWkRwbGJITn
                BPbFpCVkVWVExVSTJNRFkwTlRrd01DSXNJbVY0Y0NJNk1UY3lNREF6TURBd015d2lhV0YwSWpveE56RTNORE00TURBekxDSjJZeUk
                2ZXlKQVkyOXVkR1Y0ZENJNld5Sm9kSFJ3Y3pvdkwzZDNkeTUzTXk1dmNtY3Zibk12WTNKbFpHVnVkR2xoYkhNdmRqSWlMQ0pvZEhS
                d2N6b3ZMM2QzZHk1bGRtbGtaVzVqWld4bFpHZGxjaTVsZFM4eU1ESXlMMk55WldSbGJuUnBZV3h6TDJWdGNHeHZlV1ZsTDNZeElsM
                HNJbWxrSWpvaU9HTTNZVFl5TVRNdE5UUTBaQzAwTlRCa0xUaGxNMlF0WWpReFptRTVNREE1TVRrNElpd2lkSGx3WlNJNld5SldaWE
                pwWm1saFlteGxRM0psWkdWdWRHbGhiQ0lzSWt4RlFWSkRjbVZrWlc1MGFXRnNSVzF3Ykc5NVpXVWlYU3dpYVhOemRXVnlJanA3SW1
                sa0lqb2laR2xrT21Wc2MyazZWa0ZVUlZNdFFqWXdOalExT1RBd0luMHNJbWx6YzNWaGJtTmxSR0YwWlNJNklqSXdNalF0TURVdE1U
                TWdNRFU2TWpBNk16TXVOakV5TVRnNE56azNJQ3N3TURBd0lGVlVReUlzSW5aaGJHbGtSbkp2YlNJNklqSXdNalF0TURVdE1UTWdNR
                FU2TWpBNk16TXVOakV5TVRnNE56azNJQ3N3TURBd0lGVlVReUlzSW1WNGNHbHlZWFJwYjI1RVlYUmxJam9pTWpBeU5TMHdOUzB4TX
                lBd05Ub3lNRG96TXk0Mk1USXhPRGczT1RjZ0t6QXdNREFnVlZSRElpd2lZM0psWkdWdWRHbGhiRk4xWW1wbFkzUWlPbnNpYldGdVp
                HRjBaU0k2ZXlKcFpDSTZJamRpWmpVMVpESmxMVFV5TkRjdE5EY3hOQzA1TVdReExUaGxNbVk0WTJJM016QmtNU0lzSW14cFptVmZj
                M0JoYmlJNmV5SmxibVJmWkdGMFpWOTBhVzFsSWpvaU1qQXlOQzB3TmkweU9WUXdOem8wTnpvek9DNDFPVFl4TkRVME5UbGFJaXdpY
                zNSaGNuUmZaR0YwWlY5MGFXMWxJam9pTWpBeU5DMHdOUzB6TUZRd056bzBOem96T0M0MU9UWXhORFUwTlRsYUluMHNJbTFoYm1SaG
                RHVmxJanA3SW1sa0lqb2laR2xrT210bGVUcDZSRzVoWlhCaVVXdE1ibmwzV0RSSFNITnVjRlIxUjFGclFraDBTalJWYmtkTk9UZDB
                jemRZZFUweU56Tk1NV2xvSWl3aVpXMWhhV3dpT2lKeWRXSmxiaTV0YjJSaGJXbHZRR2x1TWk1bGN5SXNJbVpwY25OMFgyNWhiV1Vp
                T2lKU2RXSmxiaUlzSW14aGMzUmZibUZ0WlNJNklrMXZaR0Z0YVc4aUxDSnRiMkpwYkdWZmNHaHZibVVpT2lJck16UWdOams1T1RrN
                U9UazVJbjBzSW0xaGJtUmhkRzl5SWpwN0ltTnZiVzF2Yms1aGJXVWlPaUpKVGpJaUxDSmpiM1Z1ZEhKNUlqb2lSVk1pTENKbGJXRn
                BiRUZrWkhKbGMzTWlPaUp5Y21ob1FHbHVNaTVsY3lJc0ltOXlaMkZ1YVhwaGRHbHZiaUk2SWtsT01pd2dTVzVuWlc1cFpYTERyV0V
                nWkdVZ2JHRWdTVzVtYjNKdFlXTnB3N051TENCVExrd3VJaXdpYjNKbllXNXBlbUYwYVc5dVNXUmxiblJwWm1sbGNpSTZJbFpCVkVW
                VExVSTJNRFkwTlRrd01DSXNJbk5sY21saGJFNTFiV0psY2lJNklrSTJNRFkwTlRrd01DSjlMQ0p3YjNkbGNpSTZXM3NpYVdRaU9pS
                m1NR1F4TXpObVpTMHlZakpsTFRSbVpXRXRPV1ExT0MwNE5tSXlZelJtWVdGaE9Ua2lMQ0owYldaZllXTjBhVzl1SWpvaVJYaGxZM1
                YwWlNJc0luUnRabDltZFc1amRHbHZiaUk2SWs5dVltOWhjbVJwYm1jaUxDSjBiV1pmZEhsd1pTSTZJa1J2YldGcGJpSjlMSHNpYVd
                RaU9pSmhPRFJtT0Rsa1lTMWlZV0kyTFRSbVpEUXRPR0k0WVMwNU5EaGlNRGxsTkRrd09ERWlMQ0owYldaZllXTjBhVzl1SWpwYklr
                OXdaWEpoZEc5eUlpd2lUV0Z5YTJWMGNHeGhZMlVpWFN3aWRHMW1YMloxYm1OMGFXOXVJam9pUkc5dFpWQnNZWFJtYjNKdElpd2lkR
                zFtWDNSNWNHVWlPaUpFYjIxaGFXNGlmVjBzSW5OcFoyNWxjaUk2ZXlKamIyMXRiMjVPWVcxbElqb2lTVTR5SWl3aVkyOTFiblJ5ZV
                NJNklrVlRJaXdpWlcxaGFXeEJaR1J5WlhOeklqb2ljbkpvYUVCcGJqSXVaWE1pTENKdmNtZGhibWw2WVhScGIyNGlPaUpKVGpJc0l
                FbHVaMlZ1YVdWeXc2MWhJR1JsSUd4aElFbHVabTl5YldGamFjT3piaXdnVXk1TUxpSXNJbTl5WjJGdWFYcGhkR2x2Ymtsa1pXNTBh
                V1pwWlhJaU9pSldRVlJGVXkxQ05qQTJORFU1TURBaUxDSnpaWEpwWVd4T2RXMWlaWElpT2lKQ05qQTJORFU1TURBaWZYMTlmU3dpY
                W5ScElqb2lOelExT1RNNVl6QXROR1JpWmkwME5URmlMV0V5TVRNdE16SmtaalJtTURkak1qWTBJbjAuRDhMTUFXeG5KS3c5OWZpd2
                pyUHZqSEpxUUZzNS1kZTQyWXJ2aS1Qa0c3QUozVVVMMm0zVmhtYjczMnVmVlMtVDh4SHFyUktZTHJGcVRVaWxiak9UaTh5NDhIZ1p
                2RkxSc0tpdm5SdnI2R2IyM0Q5eDJScVRJSEtXUjVjZUxjZnp3WFlsM3VsT0tKRDVEcTl4NFpJNktMMERJaGx1M29nOXRZajYyaE9m
                SmpjcGd4UlVZMktUeWVLOVBMRklOLUJ2NFJXQTBvdEQ2QW5ESXY1SjNXSDlaZ0M2TFdiXy1XZm9CRlJGWVlWc1BYbmt6Ml9lN3dkM
                nlsVGg2cTVtVUZyOFJqSjVlWmFNRHdhMG5uNVFhUVpSeE9sTVBRc2o4ekFIaFRWWnVhUnpEWXFCOUFEV2RtVEtxYnZaYTFwQ2V3eV
                I1QkNfLURNSkZxR0dJSEc5WUJIVjY2NVF6LXkweldFal95VXJnVHlJRnY5UEpTN2hkWVh1ZnZJVnVLNmZHZTVIRzJrMUhxSWlFbmh
                KaEFLQWtza1FZYnBTQnBjUVVzQ3dKYmFCbnlWNnBJMnhZdjlyM1NKSF82NG81eFQzYXVtbmtjcDNrdkZxeHowZThkSUg2RkpidjhQ
                ZkV3RXdaWVhMeHozR1pab3BUSWJpRndZYzdidlJVOW5ZbTk2b2tqOGF1UGhmX2NhbWdoRzU4VUlzRVhnLU5yLWJ4aS1NM3BLNU5GL
                Xd3TjZEWHlITjVlUUFIbDB2cTBQS3FVYUliOGxJVzRDbnNfNHRCcUhwcVloRFNMY0NmN09Kb2NnVnJrNjYwUzBvazE4cjN5dTRTMz
                lkNXhWRUJPMXk3bzVlVUNOWkRqbGx2d2gwa2prZ202M0NJei1FcW9TbnhvYlRPNzltM29SR0NoM2wzN28iXX0sImV4cCI6MTcxODA
                xNTYzNiwiaWF0IjoxNzE4MDE1NDU2LCJqdGkiOiJ1cm46dXVpZDo0MWFjYWRhMy02N2I0LTQ5NGUtYTZlMy1lMDk2NjQ0OWYyNWQi
                fQ.0MmyF0EIGL-9DA1I1Q6qUcCFFEKX7LnXy6s7tkpWtqynzGuvm_4SyAyQFpZrGHwhVSvCBhLkb5UPGEPE_sDgJg
                """;
        byte[] publicKeyBytes = getPublicKeyBytesFromDid("did:key:zDnaepbQkLnywX4GHsnpTuGQkBHtJ4UnGM97ts7XuM273L1ih");
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

}