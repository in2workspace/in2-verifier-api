package es.in2.vcverifier.service;

import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import es.in2.vcverifier.exception.DidKeyDecodeException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bitcoinj.base.Base58;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

@Slf4j
@Service
@RequiredArgsConstructor
public class DIDServiceImpl implements DIDService {

    public String createDidKey() {

        return null;
    }

    public ECPublicKey getPublicKeyFromDidKey(String did) {

        if (!did.startsWith("did:key:")) {
            throw new IllegalArgumentException("The DID is not a did:key type");
        }

        // Extract the multibase base58-btc encoded value
        String multibaseValue = did.substring("did:key:".length());
        byte[] multibaseValueBytes = Base58.decode(multibaseValue);
        // 0xe7 equals secp256k1 signature
        if (multibaseValueBytes[0] == (byte)0xe7) {
            try {
                // Delete prefix
                byte[] publicKeyBytes = Arrays.copyOfRange(multibaseValueBytes, 1, multibaseValueBytes.length);
                // Create ECPoint used to generate the ECPublicKey
                int keyLength = (publicKeyBytes.length - 1) / 2;
                byte[] xBytes = Arrays.copyOfRange(publicKeyBytes, 1, keyLength + 1);
                byte[] yBytes = Arrays.copyOfRange(publicKeyBytes, keyLength + 1, publicKeyBytes.length);

                ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
                KeyFactory keyFactory = KeyFactory.getInstance("EC", BouncyCastleProviderSingleton.getInstance());

                ECPoint ecPoint = new ECPoint(new BigInteger(1, xBytes), new BigInteger(1, yBytes));

                ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(ecPoint, ecSpec);
                ECPublicKey publicKey = (ECPublicKey) keyFactory.generatePublic(ecPublicKeySpec);

                return (ECPublicKey) publicKey;
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new DidKeyDecodeException("Error decoding did:key");
            }
        } else {
            throw new IllegalArgumentException("Tipo de clave no soportado o formato desconocido");
        }
    }

}
