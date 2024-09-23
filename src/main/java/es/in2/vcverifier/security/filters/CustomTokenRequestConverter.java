package es.in2.vcverifier.security.filters;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.config.CacheStore;
import es.in2.vcverifier.exception.InvalidCredentialTypeException;
import es.in2.vcverifier.exception.UnsupportedGrantTypeException;
import es.in2.vcverifier.model.AuthorizationCodeData;
import es.in2.vcverifier.model.LEARCredentialMachine;
import es.in2.vcverifier.model.LEARCredentialType;
import es.in2.vcverifier.service.ClientAssertionValidationService;
import es.in2.vcverifier.service.JWTService;
import es.in2.vcverifier.service.VpService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@RequiredArgsConstructor
public class CustomTokenRequestConverter implements AuthenticationConverter {

    private final JWTService jwtService;
    private final ClientAssertionValidationService clientAssertionValidationService;
    private final VpService vpService;
    private final CacheStore<AuthorizationCodeData> cacheStoreForAuthorizationCodeData;
    private final OAuth2AuthorizationService oAuth2AuthorizationService;
    private final ObjectMapper objectMapper;



    @Override
    public Authentication convert(HttpServletRequest request) {
        log.info("CustomTokenRequestConverter --> convert -- INIT");
        MultiValueMap<String, String> parameters = getParameters(request);
        // grant_type (REQUIRED)
        String grantType = parameters.getFirst(OAuth2ParameterNames.GRANT_TYPE);

        assert grantType != null;
        return switch (grantType) {
            case "authorization_code" -> handleH2MGrant(parameters,request);
            case "client_credentials" -> handleM2MGrant(parameters);
            default -> throw new UnsupportedGrantTypeException("Unsupported grant_type: " + grantType);
        };

    }

    private Authentication handleH2MGrant(MultiValueMap<String, String> parameters,HttpServletRequest request) {
        String code = parameters.getFirst(OAuth2ParameterNames.CODE);
        String state = parameters.getFirst(OAuth2ParameterNames.STATE);
        String clientId = parameters.getFirst(OAuth2ParameterNames.CLIENT_ID);
        String clientDomain = getClientDomain(request);

        AuthorizationCodeData authorizationCodeData = cacheStoreForAuthorizationCodeData.get(code);
        // Remove the state from cache after retrieving the Object
        cacheStoreForAuthorizationCodeData.delete(code);

        // Remove the authorization from the initial request
        oAuth2AuthorizationService.remove(authorizationCodeData.oAuth2Authorization());

        if (!authorizationCodeData.state().equals(state)) {
            log.error("State mismatch. Expected: {}, Actual: {}", authorizationCodeData.state(), state);
            throw new IllegalArgumentException("Invalid state parameter");
        }

        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

        // 3. Generar un JWT que contenga la VC como un claim
        log.info("Authorization code grant successfully handled");

        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put(OAuth2ParameterNames.CLIENT_ID,clientId);
        additionalParameters.put("vc",authorizationCodeData.verifiableCredential());
        additionalParameters.put(OAuth2ParameterNames.AUDIENCE,clientDomain);

        return new OAuth2AuthorizationCodeAuthenticationToken(code, clientPrincipal, null,additionalParameters);
    }

    private Authentication handleM2MGrant(MultiValueMap<String, String> parameters) {

        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

        String clientId = parameters.getFirst(OAuth2ParameterNames.CLIENT_ID);
        String clientAssertion = parameters.getFirst(OAuth2ParameterNames.CLIENT_ASSERTION);

        SignedJWT signedJWT = jwtService.parseJWT(clientAssertion);
        Payload payload = jwtService.getPayloadFromSignedJWT(signedJWT);
        String vpToken = jwtService.getClaimFromPayload(payload,"vp_token");

        // Check if VC is LEARCredentialMachine Type
        JsonNode vc = vpService.getCredentialFromTheVerifiablePresentationAsJsonNode(vpToken);
        LEARCredentialMachine learCredentialMachine = objectMapper.convertValue(vc, LEARCredentialMachine.class);
        List<String> types = learCredentialMachine.type();
        if (!types.contains(LEARCredentialType.LEARCredentialMachine.getValue())){
            log.error("LEARCredentialType Expected: {}", LEARCredentialType.LEARCredentialMachine.getValue());
            throw new InvalidCredentialTypeException("Invalid LEARCredentialType. Expected LEARCredentialMachine");
        }

        // Check Client Assertion JWT Claims
        boolean isValid = clientAssertionValidationService.validateClientAssertionJWTClaims(clientId,payload);
        if (!isValid) {
            log.error("JWT claims from assertion are invalid");
            throw new IllegalArgumentException("Invalid JWT claims from assertion");
        }

        // Validate VP
        isValid = vpService.validateVerifiablePresentation(vpToken);
        if (!isValid) {
            log.error("VP Token is invalid");
            throw new IllegalArgumentException("Invalid VP Token");
        }
        log.info("VP Token validated successfully");

        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put(OAuth2ParameterNames.CLIENT_ID,clientId);
        additionalParameters.put("vc",vc);
        return new OAuth2ClientCredentialsAuthenticationToken(clientPrincipal,null,additionalParameters);
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

    private String getClientDomain(HttpServletRequest request) {
        // Intentar obtener el dominio desde el header "Origin"
        String origin = request.getHeader("Origin");
        if (origin != null) {
            return origin;
        }

        // Si no está presente, intentar con el header "Referer"
        String referer = request.getHeader("Referer");
        if (referer != null) {
            try {
                URL url = new URL(referer);
                return url.getHost();
            } catch (MalformedURLException e) {
                log.error("Invalid Referer URL: {}", referer);
                throw new OAuth2AuthenticationException("Invalid Referer URL: " + referer);
            }
        }

        // Si no se puede obtener, lanzar una excepción indicando que falta el dominio
        log.error("Missing domain information in request headers 'Origin' or 'Referer'");
        throw new OAuth2AuthenticationException("Missing domain information in request headers 'Origin' or 'Referer'");
    }

}
