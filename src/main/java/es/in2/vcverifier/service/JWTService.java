package es.in2.vcverifier.service;

import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.model.KeyType;

import java.security.PublicKey;

public interface JWTService {

    String generateJWT(String payload);

    void verifyJWTSignature(String jwt, PublicKey publicKey, KeyType keyType);
    SignedJWT parseJWT(String jwt);

}
