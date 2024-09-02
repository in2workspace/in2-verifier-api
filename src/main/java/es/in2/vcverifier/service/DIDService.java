package es.in2.vcverifier.service;

public interface DIDService {
    byte[] getPublicKeyBytesFromDid(String did);
}
