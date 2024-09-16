package es.in2.vcverifier.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.crypto.CryptoComponent;
import es.in2.vcverifier.exception.JWTCreationException;
import es.in2.vcverifier.exception.JWTVerificationException;
import es.in2.vcverifier.service.JWTService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
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

    public void verifyJWTSignature(String jwt, PublicKey publicKey) {
        try {
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


}
