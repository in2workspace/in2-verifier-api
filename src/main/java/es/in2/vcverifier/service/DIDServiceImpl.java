package es.in2.vcverifier.service;

import io.github.novacrypto.base58.Base58;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class DIDServiceImpl implements DIDService {

    public String createDidKey() {

        return null;
    }

    public byte[] getPublicKeyBytesFromDid(String did) {
        if (!did.startsWith("did:key:")) {
            throw new IllegalArgumentException("Unsupported DID type. Only did:key is supported for the moment.");
        }

        // Remove the "did:key:" prefix to get the actual encoded public key
        String encodedPublicKey = did.substring("did:key:".length());

        // Decode the public key from its encoded representation
        return decodePublicKeyIntoBytes(encodedPublicKey);
    }

    private byte[] decodePublicKeyIntoBytes(String publicKey) {
        // Remove the prefix "z" to get the multibase encoded string
        if (!publicKey.startsWith("z")) {
            throw new IllegalArgumentException("Invalid Public Key.");
        }
        String multibaseEncoded = publicKey.substring(1);

        // Multibase decode (Base58) the encoded part to get the bytes
        byte[] decodedBytes = Base58.base58Decode(multibaseEncoded);

        // Multicodec prefix is fixed for "0x1200" for the secp256r1 curve
        int prefixLength = 2;

        // Extract public key bytes after the multicodec prefix
        byte[] publicKeyBytes = new byte[decodedBytes.length - prefixLength];
        System.arraycopy(decodedBytes, prefixLength, publicKeyBytes, 0, publicKeyBytes.length);

        return publicKeyBytes;
    }

}
