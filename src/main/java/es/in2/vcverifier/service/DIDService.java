package es.in2.vcverifier.service;

import java.security.PublicKey;

public interface DIDService {
    PublicKey getPublicKeyFromDid(String did);
    byte[] getPublicKeyBytesFromDid(String did);
}
