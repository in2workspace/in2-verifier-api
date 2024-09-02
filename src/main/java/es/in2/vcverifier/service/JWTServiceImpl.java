package es.in2.vcverifier.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.crypto.CryptoComponent;
import es.in2.vcverifier.exception.JWTCreationException;
import es.in2.vcverifier.exception.JWTVerificationException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.text.ParseException;
import java.util.Arrays;

@Slf4j
@Service
@RequiredArgsConstructor
public class JWTServiceImpl implements JWTService {

    private final CryptoComponent cryptoComponent;

    @Override
    public String generateJWT(String payload) {
        try {
            // Get ECKey
            ECKey ecJWK = cryptoComponent.getECKey();
            // Set Header
            JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.ES256K)
                    .keyID(cryptoComponent.getECKey().getKeyID())
                    .build();
            // Set Payload
            // todo: create a mapper with payload and claim set
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().build();
            // Create JWT for ES256K algorithm
            SignedJWT jwt = new SignedJWT(jwsHeader, claimsSet);
            // Sign with a private EC key
            jwt.sign(new ECDSASigner(ecJWK));
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new JWTCreationException("Error creating JWT");
        }
    }

    public void verifyJWTSignature(String jwt, byte[] publicKeyBytes) {
        try {
            // Set the curve as secp256r1
            ECCurve curve = new SecP256R1Curve();
            BigInteger x = new BigInteger(1, Arrays.copyOfRange(publicKeyBytes, 1, publicKeyBytes.length));

            // Recover the Y coordinate from the X coordinate and the curve
            BigInteger y = curve.decodePoint(publicKeyBytes).getYCoord().toBigInteger();
            ECPoint point = new ECPoint(x, y);

            // Get the ECParameterSpec for secp256r1
            ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
            ECNamedCurveSpec params = new ECNamedCurveSpec("secp256r1", ecSpec.getCurve(), ecSpec.getG(), ecSpec.getN());

            // Create a KeyFactory and generate the public key
            KeyFactory kf = KeyFactory.getInstance("EC");
            ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, params);
            ECPublicKey publicKey = (ECPublicKey) kf.generatePublic(pubKeySpec);

            // Parse the JWT and create a verifier
            SignedJWT signedJWT = SignedJWT.parse(jwt);
            ECDSAVerifier verifier = new ECDSAVerifier(publicKey);

            // Verify the signature
            if (!signedJWT.verify(verifier)) {
                throw new JWTVerificationException("Invalid JWT signature");
            }
        } catch (Exception e) {
            throw new RuntimeException("JWT signature verification failed.", e);
        }
    }


}
