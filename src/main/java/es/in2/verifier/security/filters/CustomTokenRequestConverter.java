package es.in2.verifier.security.filters;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.SignedJWT;
import es.in2.verifier.config.CacheStore;
import es.in2.verifier.exception.InvalidCredentialTypeException;
import es.in2.verifier.exception.InvalidVPtokenException;
import es.in2.verifier.exception.UnsupportedGrantTypeException;
import es.in2.verifier.model.AuthorizationCodeData;
import es.in2.verifier.model.RefreshTokenDataCache;
import es.in2.verifier.model.credentials.lear.machine.LEARCredentialMachine;
import es.in2.verifier.model.enums.LEARCredentialType;
import es.in2.verifier.service.ClientAssertionValidationService;
import es.in2.verifier.service.JWTService;
import es.in2.verifier.service.VpService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.springframework.security.oauth2.core.oidc.IdTokenClaimNames.NONCE;

@Slf4j
@RequiredArgsConstructor
public class CustomTokenRequestConverter implements AuthenticationConverter {

    private final JWTService jwtService;
    private final ClientAssertionValidationService clientAssertionValidationService;
    private final VpService vpService;
    private final CacheStore<AuthorizationCodeData> cacheStoreForAuthorizationCodeData;
    private final OAuth2AuthorizationService oAuth2AuthorizationService;
    private final ObjectMapper objectMapper;
    private final CacheStore<RefreshTokenDataCache> refreshTokenDataCacheCacheStore;

    @Override
    public Authentication convert(HttpServletRequest request) {
        log.info("CustomTokenRequestConverter --> convert -- INIT");
        MultiValueMap<String, String> parameters = getParameters(request);
        // grant_type (REQUIRED)
        String grantType = parameters.getFirst(OAuth2ParameterNames.GRANT_TYPE);
        assert grantType != null;
        return switch (grantType) {
            case "authorization_code" -> handleAuthorizationCodeGrant(parameters);
            case "client_credentials" -> handleClientCredentialsGrant(parameters);
            case "refresh_token" -> handleRefreshTokenGrant(parameters);
            default -> throw new UnsupportedGrantTypeException("Unsupported grant_type: " + grantType);
        };
    }

    private Authentication handleAuthorizationCodeGrant(MultiValueMap<String, String> parameters) {
        log.info("CustomTokenRequestConverter -->  handleAuthorizationCodeGrant -- INIT");
        String code = parameters.getFirst(OAuth2ParameterNames.CODE);
        String state = parameters.getFirst(OAuth2ParameterNames.STATE);
        String clientId = parameters.getFirst(OAuth2ParameterNames.CLIENT_ID);
        AuthorizationCodeData authorizationCodeData = cacheStoreForAuthorizationCodeData.get(code);
        // Remove the state from cache after retrieving the Object
        cacheStoreForAuthorizationCodeData.delete(code);
        // Remove the authorization from the initial request
        oAuth2AuthorizationService.remove(authorizationCodeData.oAuth2Authorization());
        // Check state only if it is not null and not blank
        if (state != null && !state.isBlank() && (!authorizationCodeData.state().equals(state))) {
                log.error("CustomTokenRequestConverter --  handleAuthorizationCodeGrant -- State mismatch. Expected: {}, Actual: {}", authorizationCodeData.state(), state);
                throw new IllegalArgumentException("Invalid state parameter");
        }

        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();
        // 3. Generar un JWT que contenga la VC como un claim
        log.info("Authorization code grant successfully handled");
        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put(OAuth2ParameterNames.CLIENT_ID, clientId);
        additionalParameters.put("vc", authorizationCodeData.verifiableCredential());
        additionalParameters.put(OAuth2ParameterNames.SCOPE, String.join(" ", authorizationCodeData.requestedScopes()));
        additionalParameters.put(OAuth2ParameterNames.AUDIENCE, clientId);
        additionalParameters.put(NONCE, authorizationCodeData.clientNonce());
        return new OAuth2AuthorizationCodeAuthenticationToken(code, clientPrincipal, null, additionalParameters);
    }

    private Authentication handleClientCredentialsGrant(MultiValueMap<String, String> parameters) {
        log.info("CustomTokenRequestConverter --> handleClientCredentialsGrant -- INIT");
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
        if (!types.contains(LEARCredentialType.LEAR_CREDENTIAL_MACHINE.getValue())){
            log.error("CustomTokenRequestConverter -- handleClientCredentialsGrant-- LEARCredentialType Expected: {}", LEARCredentialType.LEAR_CREDENTIAL_MACHINE.getValue());
            throw new InvalidCredentialTypeException("Invalid LEARCredentialType. Expected LEARCredentialMachine");
        }
        // Check Client Assertion JWT Claims
        boolean isValid = clientAssertionValidationService.validateClientAssertionJWTClaims(clientId,payload);
        if (!isValid) {
            log.error("CustomTokenRequestConverter -- handleClientCredentialsGrant -- JWT claims from assertion are invalid");
            throw new IllegalArgumentException("Invalid JWT claims from assertion");
        }
        // Validate VP
        isValid = vpService.validateVerifiablePresentation(vpToken);
        if (!isValid) {
            log.error("CustomTokenRequestConverter -- handleClientCredentialsGrant -- VP Token is invalid");
            throw new InvalidVPtokenException("VP Token used in M2M flow is invalid");
        }
        log.info("VP Token validated successfully");
        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put(OAuth2ParameterNames.CLIENT_ID,clientId);
        additionalParameters.put("vc",vc);
        return new OAuth2ClientCredentialsAuthenticationToken(clientPrincipal,null,additionalParameters);
    }

    private Authentication handleRefreshTokenGrant(MultiValueMap<String, String> parameters) {
        log.info("CustomTokenRequestConverter --> handleRefreshTokenGrant -- INIT");

        String refreshTokenValue = parameters.getFirst(OAuth2ParameterNames.REFRESH_TOKEN);
        String clientId = parameters.getFirst(OAuth2ParameterNames.CLIENT_ID);

        // Retrieving the object related to the refresh token from the cache
        RefreshTokenDataCache refreshTokenDataCache = refreshTokenDataCacheCacheStore.get(refreshTokenValue);

        if (refreshTokenDataCache == null) {
            log.error("CustomTokenRequestConverter -- handleRefreshTokenGrant -- Refresh token not found or expired");
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_TOKEN);
        }

        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put(OAuth2ParameterNames.CLIENT_ID, clientId);
        additionalParameters.put("vc", refreshTokenDataCache.verifiableCredential());

        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

        log.info("Refresh token grant successfully handled");
        return new OAuth2RefreshTokenAuthenticationToken(refreshTokenValue, clientPrincipal, null, additionalParameters);
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
