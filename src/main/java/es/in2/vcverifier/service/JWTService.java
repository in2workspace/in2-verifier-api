package es.in2.vcverifier.service;

import com.nimbusds.jwt.SignedJWT;

public interface JWTService {

    String generateJWT(String payload);

    void verifyJWTSignature(String jwt, byte[] publicKeyBytes);

}
