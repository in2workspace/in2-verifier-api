package es.in2.vcverifier.crypto;

import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import lombok.RequiredArgsConstructor;
import org.bitcoinj.base.Base58;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

@Configuration
@RequiredArgsConstructor
public class CryptoComponent {

    private final CryptoConfig cryptoConfig;

    @Bean
    public ECKey getECKey() {
        return buildEcKeyFromPrivateKey();
    }

    /**
     * Documentation: <a href="https://connect2id.com/products/nimbus-jose-jwt/examples/jwt-with-es256k-signature">JSON Web Token (JWT) with ES256K (secp256k1) signature</a>
     *
     * @return - ECKey
     */
    private ECKey buildEcKeyFromPrivateKey() {
        try {
            BigInteger privateKeyInt = new BigInteger(cryptoConfig.getPrivateKey(), 16);
            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
            KeyFactory keyFactory = KeyFactory.getInstance("EC", BouncyCastleProviderSingleton.getInstance());
            ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(privateKeyInt, ecSpec);
            ECPrivateKey privateKey = (ECPrivateKey) keyFactory.generatePrivate(privateKeySpec);
            ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(ecSpec.getG().multiply(privateKeyInt), ecSpec);
            ECPublicKey publicKey = (ECPublicKey) keyFactory.generatePublic(publicKeySpec);
            return new ECKey.Builder(Curve.SECP256K1, publicKey).privateKey(privateKey).keyID(generateDidKey(publicKey)).build();
        } catch (Exception e) {
            throw new ECKeyCreationException("Error creating JWK source");
        }
    }

    /**
     * Documentation: <a href="https://w3c-ccg.github.io/did-method-key/#dfn-did-key">The did:key Method v0.7 - A DID Method for Static Cryptographic Keys</a>
     *
     * @param ecPublicKey - Public key
     * @return - did:key identifier
     */
    private static String generateDidKey(ECPublicKey ecPublicKey) {
        try {
            // Get the bytes of the public key
            byte[] publicKeyBytes = ecPublicKey.getEncoded();
            // Multicodec identifier for SECP256K1 (0xe7)
            byte multicodecIdentifier = (byte) 0xE7;
            // Concatenate Multicodec with the public key
            ByteBuffer buffer = ByteBuffer.allocate(1 + publicKeyBytes.length);
            buffer.put(multicodecIdentifier);
            buffer.put(publicKeyBytes);
            byte[] combinedBytes = buffer.array();
            // Encode with Base58-btc (Multibase)
            String mbValue = "z" + Base58.encode(combinedBytes);
            // Add did:key prefix
            return "did:key:" + mbValue;
        } catch (Exception e) {
            throw new DidKeyCreationException("Error generating DID key");
        }
    }

}
