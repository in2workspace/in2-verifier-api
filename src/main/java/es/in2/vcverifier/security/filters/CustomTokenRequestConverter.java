package es.in2.vcverifier.security.filters;

import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.exception.UnsupportedGrantTypeException;
import es.in2.vcverifier.service.ClientAssertionValidationService;
import es.in2.vcverifier.service.JWTService;
import es.in2.vcverifier.service.VpValidationService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.Map;

@Slf4j
@RequiredArgsConstructor
public class CustomTokenRequestConverter implements AuthenticationConverter {

    private final JWTService jwtService;
    private final VpValidationService vpValidationService;
    private final ClientAssertionValidationService clientAssertionValidationService;

    @Override
    public Authentication convert(HttpServletRequest request) {
        log.info("CustomTokenRequestConverter --> convert -- INIT");

        // grant_type (REQUIRED)
        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);

        return switch (grantType) {
            case "authorization_code " -> handleH2MGrant(request);
            case "client_credentials" -> handleM2MGrant(request);
            default -> throw new UnsupportedGrantTypeException("Unsupported grant_type: " + grantType);
        };

    }

    private Authentication handleH2MGrant(HttpServletRequest request) {
        //TODO H2M implementation
        return null;
    }

    private Authentication handleM2MGrant(HttpServletRequest request) {

        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

        MultiValueMap<String, String> parameters = getParameters(request);

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
        payload = jwtService.getPayloadFromSignedJWT(signedJWT);
        String vp = jwtService.getClaimFromPayload(payload,"vp");

        isValid = vpValidationService.validateVerifiablePresentation(vp);
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
