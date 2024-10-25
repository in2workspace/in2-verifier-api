package es.in2.vcverifier.service;

import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.model.enums.KeyType;

import java.security.PublicKey;

public interface JWTService {

    String generateJWT(String payload);

    void verifyJWTSignature(String jwt, PublicKey publicKey, KeyType keyType);

    SignedJWT parseJWT(String jwt);

    Payload getPayloadFromSignedJWT(SignedJWT signedJWT);

    String getClaimFromPayload(Payload payload, String claimName);

    long getExpirationFromPayload(Payload payload);

    Object getVCFromPayload(Payload payload);


}
