package es.in2.vcverifier.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.crypto.CryptoComponent;
import es.in2.vcverifier.exception.JWTCreationException;
import es.in2.vcverifier.exception.JWTVerificationException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.text.ParseException;

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

    @Override
    public void verifyJWTSignature(String jwt) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(jwt);
            // Extract the Issuer of the JWT
            String issuer = signedJWT.getJWTClaimsSet().getIssuer();
            // Get ECPublicKey from did:key
            if(issuer.contains("did:key")) {


            } else {
                throw new NoSuchMethodException("DID method is not supported");
            }
        } catch (ParseException | NoSuchMethodException e) {
            throw new JWTVerificationException("Error verifying JWT");
        }
    }

}
