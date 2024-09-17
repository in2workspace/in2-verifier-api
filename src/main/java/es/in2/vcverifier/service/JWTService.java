package es.in2.vcverifier.service;

import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.SignedJWT;

import java.security.PublicKey;

public interface JWTService {

    String generateJWT(String payload);

    void verifyJWTSignature(String jwt, PublicKey publicKey);

    SignedJWT parseJWT(String jwt);

    Payload getPayloadFromSignedJWT(SignedJWT signedJWT);

    String getIssuerFromPayload(Payload payload);

    String getSubjectFromPayload(Payload payload);

    String getAudienceFromPayload(Payload payload);

    String getJwtIdFromPayload(Payload payload);

    long getExpirationFromPayload(Payload payload);

    String getVcFromPayload(Payload payload);

}
