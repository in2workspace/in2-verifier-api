package es.in2.vcverifier.security.filters;

import com.fasterxml.jackson.databind.JsonNode;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.config.CacheStore;
import es.in2.vcverifier.crypto.CryptoComponent;
import es.in2.vcverifier.exception.UnsupportedGrantTypeException;
import es.in2.vcverifier.model.AuthorizationCodeData;
import es.in2.vcverifier.service.ClientAssertionValidationService;
import es.in2.vcverifier.service.JWTService;
import es.in2.vcverifier.service.VpService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AccessTokenResponseAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

@Slf4j
@RequiredArgsConstructor
public class CustomTokenRequestConverter implements AuthenticationConverter {

    private final JWTService jwtService;
    private final ClientAssertionValidationService clientAssertionValidationService;
    private final VpService vpService;
    private final CacheStore<AuthorizationCodeData> cacheStoreForAuthorizationCodeData;

    @Override
    public Authentication convert(HttpServletRequest request) {
        log.info("CustomTokenRequestConverter --> convert -- INIT");
        MultiValueMap<String, String> parameters = getParameters(request);
        // grant_type (REQUIRED)
        String grantType = parameters.getFirst(OAuth2ParameterNames.GRANT_TYPE);

        assert grantType != null;
        return switch (grantType) {
            case "authorization_code " -> handleH2MGrant(parameters);
            case "client_credentials" -> handleM2MGrant(parameters);
            default -> throw new UnsupportedGrantTypeException("Unsupported grant_type: " + grantType);
        };

    }

    private Authentication handleH2MGrant(MultiValueMap<String, String> parameters) {
        // 1. Obtener y validar el código y el estado
        String code = parameters.getFirst(OAuth2ParameterNames.CODE);
        String state = parameters.getFirst(OAuth2ParameterNames.STATE);

        AuthorizationCodeData authorizationCodeData = cacheStoreForAuthorizationCodeData.get(code);

        if (authorizationCodeData == null) {
            log.error("Invalid or expired authorization code: {}", code);
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }

        if (!authorizationCodeData.state().equals(state)) {
            log.error("State mismatch. Expected: {}, Actual: {}", authorizationCodeData.state(), state);
            throw new IllegalArgumentException("Invalid state parameter");
        }

        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

        // 3. Generar un JWT que contenga la VC como un claim
        log.info("Authorization code grant successfully handled");

        return new OAuth2AuthorizationCodeAuthenticationToken(code, clientPrincipal, null,null);
    }

    private Authentication handleM2MGrant(MultiValueMap<String, String> parameters) {

        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

        String clientId = parameters.getFirst(OAuth2ParameterNames.CLIENT_ID);
        String clientAssertion = parameters.getFirst(OAuth2ParameterNames.CLIENT_ASSERTION);

        SignedJWT signedJWT = jwtService.parseJWT(clientAssertion);
        Payload payload = jwtService.getPayloadFromSignedJWT(signedJWT);

        boolean isValid = clientAssertionValidationService.validateClientAssertionJWTClaims(clientId,payload);
        if (!isValid) {
            log.error("JWT claims from assertion are invalid");
            throw new IllegalArgumentException("Invalid JWT claims from assertion");
        }

        String vpToken = jwtService.getClaimFromPayload(payload,"vp_token");
        signedJWT = jwtService.parseJWT(vpToken);

        isValid = vpService.validateVerifiablePresentation(signedJWT.serialize());
        if (!isValid) {
            log.error("VP Token is invalid");
            throw new IllegalArgumentException("Invalid VP Token");
        }
        log.info("VP Token validated successfully");

        return new OAuth2ClientCredentialsAuthenticationToken(clientPrincipal,null,null);
    }

    private static MultiValueMap<String, String> getParameters(HttpServletRequest request) {
        Map<String, String[]> parameterMap = request.getParameterMap();
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>(parameterMap.size());
        parameterMap.forEach((key, values) -> {
            for (String value : values) {
                parameters.add(key, value);
            }
        });
        return parameters;
    }
}
