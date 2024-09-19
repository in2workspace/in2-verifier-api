package es.in2.vcverifier.service.impl;

import com.nimbusds.jose.Payload;
import es.in2.vcverifier.config.JtiTokenCache;
import es.in2.vcverifier.config.properties.SecurityProperties;
import es.in2.vcverifier.service.ClientAssertionValidationService;
import es.in2.vcverifier.service.JWTService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class ClientAssertionValidationServiceImpl implements ClientAssertionValidationService {

    private final SecurityProperties securityProperties;
    private final JtiTokenCache jtiTokenCache;
    private final JWTService jwtService;

    @Override
    public boolean validateClientAssertionJWTClaims(String clientId, Payload payload) {
        return validateIssuerAndSubject(clientId, payload) &&
                validateAudience(payload) &&
                //validateJti(payload) &&
                validateExpiration(payload);
    }

    private boolean validateIssuerAndSubject(String clientId, Payload payload) {
        return validateIfIssuerMatchesWithClientId(clientId, payload) && validateIfSubjectMatchesWithClientId(clientId, payload);
    }

    private boolean validateIfIssuerMatchesWithClientId(String clientId, Payload payload) {
        String iss = jwtService.getClaimFromPayload(payload, "iss");
        if (!iss.equals(clientId)) {
            log.error("VpValidationServiceImpl -- validateIssuer -- The 'iss' (issuer) claim does not match the clientId.");
            return false;
        }
        return true;
    }

    private boolean validateIfSubjectMatchesWithClientId(String clientId, Payload payload) {
        String sub = jwtService.getClaimFromPayload(payload, "sub");
        if (!sub.equals(clientId)) {
            log.error("VpValidationServiceImpl -- validateSubject -- The 'sub' (subject) claim does not match the clientId.");
            return false;
        }
        return true;
    }

    private boolean validateAudience(Payload payload) {
        String aud = jwtService.getClaimFromPayload(payload, "aud");
        String expectedAudience = securityProperties.authorizationServer();

        if (!aud.equals(expectedAudience)) {
            log.error("VpValidationServiceImpl -- validateAudience -- The 'aud' (audience) claim does not match the expected audience.");
            return false;
        }
        return true;
    }

    private boolean validateJti(Payload payload) {
        String jti = jwtService.getClaimFromPayload(payload, "jti");

        if (jtiTokenCache.isJtiPresent(jti)) {
            log.error("VpValidationServiceImpl -- validateJti -- The token with jti: {} has already been used.", jti);
            return false;
        } else {
            jtiTokenCache.addJti(jti);
        }
        return true;
    }

    private boolean validateExpiration(Payload payload) {
        long exp = jwtService.getExpirationFromPayload(payload);
        long currentTimeInSeconds = System.currentTimeMillis() / 1000;

        if (exp <= currentTimeInSeconds) {
            log.error("VpValidationServiceImpl -- validateExpiration -- The 'exp' (expiration) claim has expired.");
            return false;
        }
        return true;
    }
}
