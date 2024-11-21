package es.in2.verifier.service;

import java.security.PublicKey;

public interface DIDService {
    PublicKey getPublicKeyFromDid(String did);
}
