package es.in2.verifier.domain.service;

import java.security.PublicKey;

public interface DIDService {
    PublicKey retrivePublicKeyFromP256DidKey(String did);
}
