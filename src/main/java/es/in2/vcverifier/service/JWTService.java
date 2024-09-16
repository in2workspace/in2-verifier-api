package es.in2.vcverifier.service;

import com.nimbusds.jwt.SignedJWT;

import java.security.PublicKey;

public interface JWTService {

    String generateJWT(String payload);

    void verifyJWTSignature(String jwt, PublicKey publicKey);

}
