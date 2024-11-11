package es.in2.vcverifier.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.crypto.impl.CriticalHeaderParamsDeferral;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.component.CryptoComponent;
import es.in2.vcverifier.exception.JWTClaimMissingException;
import es.in2.vcverifier.exception.JWTCreationException;
import es.in2.vcverifier.exception.JWTParsingException;
import es.in2.vcverifier.exception.JWTVerificationException;
import es.in2.vcverifier.model.enums.KeyType;
import es.in2.vcverifier.service.JWTService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

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
                    .type(JOSEObjectType.JWT)
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
            log.error("Exception during JWT signature verification", e);
            throw new JWTVerificationException("JWT signature verification failed due to unexpected error" + e);
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
                // FIXME: This shouldn't be replaced by andavanced signature verification
                // Create a set with the critical headers you want to defer
                Set<String> defCriticalHeaders = new HashSet<>();
                defCriticalHeaders.add("sigT");

                // Create a policy for critical header parameters and set the deferred ones
                CriticalHeaderParamsDeferral critPolicy = new CriticalHeaderParamsDeferral();
                critPolicy.setDeferredCriticalHeaderParams(defCriticalHeaders);

                yield new RSASSAVerifier((RSAPublicKey) publicKey, defCriticalHeaders);
            }
        };
    }


    @Override
    public SignedJWT parseJWT(String jwt) {
        try {
            return SignedJWT.parse(jwt);
        } catch (ParseException e) {
            log.error("Error al parsear el JWTs: {}", e.getMessage());
            throw new JWTParsingException("Error al parsear el JWTs");
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
            throw new JWTClaimMissingException(String.format("The '%s' claim is missing or empty in the JWT payload.", claimName));
        }
        return claimValue;
    }

    @Override
    public long getExpirationFromPayload(Payload payload) {
        Long exp = (Long) payload.toJSONObject().get("exp");
        if (exp == null || exp <= 0) {
            throw new JWTClaimMissingException("The 'exp' (expiration) claim is missing or invalid in the JWT payload.");
        }
        return exp;
    }

    @Override
    public Object getVCFromPayload(Payload payload) {
        return payload.toJSONObject().get("vc");
    }
}
