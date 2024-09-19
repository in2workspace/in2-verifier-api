package es.in2.vcverifier.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.crypto.CryptoComponent;
import es.in2.vcverifier.exception.JWTCreationException;
import es.in2.vcverifier.exception.JWTVerificationException;
import es.in2.vcverifier.model.KeyType;
import es.in2.vcverifier.service.JWTService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class JWTServiceImpl implements JWTService {

    private final CryptoComponent cryptoComponent;
    private final ObjectMapper objectMapper;

    @Override
    public String generateJWT(String payload) {
        try {
            // Get ECKey
            ECKey ecJWK = cryptoComponent.getECKey();
            // Set Header
            JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .keyID(cryptoComponent.getECKey().getKeyID())
                    .build();
            // Set Payload
            JWTClaimsSet claimsSet = convertPayloadToJWTClaimsSet(payload);
            // Create JWT for ES256R algorithm
            SignedJWT jwt = new SignedJWT(jwsHeader, claimsSet);
            // Sign with a private EC key
            JWSSigner signer = new ECDSASigner(ecJWK);
            jwt.sign(signer);
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new JWTCreationException("Error creating JWT");
        }
    }

    private JWTClaimsSet convertPayloadToJWTClaimsSet(String payload) {
        try {
            JsonNode jsonNode = objectMapper.readTree(payload);
            Map<String, Object> claimsMap = objectMapper.convertValue(jsonNode, new TypeReference<>() {
            });
            JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
            for (Map.Entry<String, Object> entry : claimsMap.entrySet()) {
                builder.claim(entry.getKey(), entry.getValue());
            }
            return builder.build();
        } catch (JsonProcessingException e) {
            log.error("Error while parsing the JWT payload", e);
            throw new JWTCreationException("Error while parsing the JWT payload");
        }

    }
    @Override
    public void verifyJWTSignature(String jwt, PublicKey publicKey, KeyType keyType) {
        try {
            // Parse the JWT
            SignedJWT signedJWT = SignedJWT.parse(jwt);

            // Create the appropriate verifier based on the key type
            JWSVerifier verifier = createVerifier(publicKey, keyType);

            // Verify the signature
            if (!signedJWT.verify(verifier)) {
                throw new JWTVerificationException("Invalid JWT signature");
            }

        } catch (Exception e) {
            throw new RuntimeException("JWT signature verification failed.", e);
        }
    }

    private JWSVerifier createVerifier(PublicKey publicKey, KeyType keyType) throws JOSEException {
        return switch (keyType) {
            case EC -> {
                if (!(publicKey instanceof ECPublicKey)) {
                    throw new IllegalArgumentException("Invalid key type for EC verification");
                }
                yield new ECDSAVerifier((ECPublicKey) publicKey);
            }
            case RSA -> {
                if (!(publicKey instanceof RSAPublicKey)) {
                    throw new IllegalArgumentException("Invalid key type for RSA verification");
                }
                yield new RSASSAVerifier((RSAPublicKey) publicKey);
            }
            default -> throw new IllegalArgumentException("Unsupported key type");
        };
    }

    @Override
    public SignedJWT parseJWT(String jwt) {
        try {
            return SignedJWT.parse(jwt);
        } catch (ParseException e) {
            //TODO Create Custom Exception
            throw new RuntimeException(e);
        }
    }

    @Override
    public Payload getPayloadFromSignedJWT(SignedJWT signedJWT) {
        return signedJWT.getPayload();
    }

    @Override
    public String getClaimFromPayload(Payload payload, String claimName) {
        String claimValue = (String) payload.toJSONObject().get(claimName);
        if (claimValue == null || claimValue.trim().isEmpty()) {
            throw new IllegalArgumentException(String.format("The '%s' claim is missing or empty in the JWT payload.", claimName));
        }
        return claimValue;
    }

    @Override
    public long getExpirationFromPayload(Payload payload) {
        Long exp = (Long) payload.toJSONObject().get("exp");
        if (exp == null || exp <= 0) {
            throw new IllegalArgumentException("The 'exp' (expiration) claim is missing or invalid in the JWT payload.");
        }
        return exp;
    }
}
