package es.in2.verifier.domain.service.impl;

import es.in2.verifier.domain.exception.PublicKeyDecodingException;
import es.in2.verifier.domain.exception.UnsupportedDIDTypeException;
import es.in2.verifier.domain.service.DIDService;
import io.github.novacrypto.base58.Base58;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;

@Slf4j
@Service
@RequiredArgsConstructor
public class DIDServiceImpl implements DIDService {

    @Override
    public PublicKey getPublicKeyFromDid(String did) {
        log.info("Attempting to retrieve public key from DID: {}", did);
        if (!did.startsWith("did:key:")) {
            log.error("DIDServiceImpl -- getPublicKeyFromDid -- Unsupported DID format detected: {}", did);
            throw new UnsupportedDIDTypeException("Unsupported DID type. Only did:key is supported for the moment.");
        }

        // Remove the "did:key:" prefix to get the actual encoded public key
        String encodedPublicKey = did.substring("did:key:".length());
        log.debug("DIDServiceImpl -- getPublicKeyFromDid -- Encoded public key extracted from DID: {}", encodedPublicKey);

        // Decode the public key from its encoded representation
        return decodePublicKeyIntoPubKey(encodedPublicKey);
    }

    private PublicKey decodePublicKeyIntoPubKey(String encodePublicKey) {
        log.info("Decoding public key from encoded string: {}", encodePublicKey);

        try {
            // Remove the prefix "z" to get the multibase encoded string
            if (!encodePublicKey.startsWith("z")) {
                log.error("DIDServiceImpl -- decodePublicKeyIntoPubKey -- Invalid public key format detected: {}", encodePublicKey);
                throw new PublicKeyDecodingException("Invalid Public Key.");
            }
            String multibaseEncoded = encodePublicKey.substring(1);

            // Multibase decode (Base58) the encoded part to get the bytes
            byte[] decodedBytes = Base58.base58Decode(multibaseEncoded);
            log.debug("DIDServiceImpl -- decodePublicKeyIntoPubKey -- Decoded bytes from Base58: {}", Arrays.toString(decodedBytes));

            // Multicodec prefix is fixed for "0x1200" for the secp256r1 curve
            int prefixLength = 2;

            // Extract public key bytes after the multicodec prefix
            byte[] publicKeyBytes = new byte[decodedBytes.length - prefixLength];
            System.arraycopy(decodedBytes, prefixLength, publicKeyBytes, 0, publicKeyBytes.length);

            // Set the curve as secp256r1
            ECCurve curve = new SecP256R1Curve();
            BigInteger x = new BigInteger(1, Arrays.copyOfRange(publicKeyBytes, 1, publicKeyBytes.length));

            // Recover the Y coordinate from the X coordinate and the curve
            BigInteger y = curve.decodePoint(publicKeyBytes).getYCoord().toBigInteger();

            log.debug("DIDServiceImpl -- decodePublicKeyIntoPubKey -- Calculated ECPoint coordinates - X: {}, Y: {}", x, y);
            ECPoint point = new ECPoint(x, y);

            // Fetch the ECParameterSpec for secp256r1
            ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
            ECNamedCurveSpec params = new ECNamedCurveSpec("secp256r1", ecSpec.getCurve(), ecSpec.getG(), ecSpec.getN());

            // Create a KeyFactory and generate the public key
            KeyFactory kf = KeyFactory.getInstance("EC");
            ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, params);

            log.info("Public key successfully decoded and generated: {}", kf.generatePublic(pubKeySpec));
            return kf.generatePublic(pubKeySpec);
        }
        catch (Exception e) {
            log.error("DIDServiceImpl -- decodePublicKeyIntoPubKey -- Failed to decode and generate public key: {}", e.getMessage(), e);
            throw new PublicKeyDecodingException("JWT signature verification failed.", e);
        }
    }


}
