package es.in2.vcverifier.security.filters;

import com.nimbusds.jose.JWSObject;
import com.nimbusds.jwt.JWTClaimsSet;
import es.in2.vcverifier.config.CacheStore;
import es.in2.vcverifier.config.properties.SecurityProperties;
import es.in2.vcverifier.crypto.CryptoComponent;
import es.in2.vcverifier.exception.RequestMismatchException;
import es.in2.vcverifier.exception.RequestObjectRetrievalException;
import es.in2.vcverifier.exception.UnsupportedScopeException;
import es.in2.vcverifier.model.AuthorizationRequestJWT;
import es.in2.vcverifier.model.enums.KeyType;
import es.in2.vcverifier.service.DIDService;
import es.in2.vcverifier.service.HttpClientService;
import es.in2.vcverifier.service.JWTService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.json.JSONObject;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.authentication.AuthenticationConverter;

import java.net.URLEncoder;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.UUID;

import static es.in2.vcverifier.util.Constants.*;

@Slf4j
@RequiredArgsConstructor
public class CustomAuthorizationRequestConverter implements AuthenticationConverter {

    private final DIDService didService;
    private final JWTService jwtService;
    private final CryptoComponent cryptoComponent;
    private final CacheStore<AuthorizationRequestJWT> cacheStoreForAuthorizationRequestJWT;
    private final CacheStore<OAuth2AuthorizationRequest> cacheStoreForOAuth2AuthorizationRequest;
    private final SecurityProperties securityProperties;
    private final HttpClientService httpClientService;
    private final RegisteredClientRepository registeredClientRepository;

    @Override
    public Authentication convert(HttpServletRequest request) {
        log.info("CustomAuthorizationRequestConverter.convert");

        String requestUri = request.getParameter(REQUEST_URI);
        String jwt;
        String clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID);
        String state = request.getParameter(OAuth2ParameterNames.STATE);
        String scope = request.getParameter(OAuth2ParameterNames.SCOPE);
        String redirectUri = request.getParameter(OAuth2ParameterNames.REDIRECT_URI);

        // Check for required client ID
        validateClientId(clientId);

        // Case 1: No 'request' or 'request_uri' is provided, assuming it's an authorization request without a signed object
        if (requestUri == null && request.getParameter("request") == null) {
            log.info("Processing an authorization request without a signed JWT object.");
            return handleNonSignedAuthorizationRequest(clientId, state, scope, redirectUri);
        }

        // Case 2: JWT present via either 'request_uri' or 'request' parameters
        jwt = retrieveJwtFromRequestUriOrRequest(requestUri, request);

        try {
            JWSObject jwsObject = JWSObject.parse(jwt);

            // Step 3: Validate the OAuth 2.0 parameters against JWT claims
            validateOAuth2Parameters(request, jwsObject);

            // Step 4: Validate the redirect_uri with the client repository
            validateRedirectUri(clientId, redirectUri, jwsObject);

            // Step 5: Process the authorization flow
            return processAuthorizationFlow(clientId, scope, state, jwsObject);
        } catch (ParseException e) {
            throw new RequestObjectRetrievalException("Error parsing the JWT: " + e.getMessage());
        }
    }

    /**
     * Handle authorization requests without a signed JWT object.
     */
    private Authentication handleNonSignedAuthorizationRequest(String clientId, String state, String scope, String redirectUri) {
        // Validate redirect_uri for non-signed requests
        validateRedirectUri(clientId, redirectUri, null);

        String nonce = generateNonce();
        String signedAuthRequest = jwtService.generateJWT(buildAuthorizationRequestJwtPayload(scope, state));

        // Cache the OAuth2 authorization request
        cacheStoreForOAuth2AuthorizationRequest.add(state, OAuth2AuthorizationRequest.authorizationCode()
                .state(state)
                .clientId(clientId)
                .redirectUri(redirectUri)
                .scope(scope)
                .authorizationUri(securityProperties.authorizationServer())
                .build());

        return getAuthentication(state, signedAuthRequest, nonce);
    }

    /**
     * Retrieve JWT from either request_uri or request parameter.
     */
    private String retrieveJwtFromRequestUriOrRequest(String requestUri, HttpServletRequest request) {
        if (requestUri != null) {
            log.info("Retrieving JWT from request_uri: {}", requestUri);
            HttpResponse<String> httpResponse = httpClientService.performGetRequest(requestUri);
            return httpResponse.body();
        }
        return request.getParameter("request");
    }

    private void validateOAuth2Parameters(HttpServletRequest request, JWSObject jwsObject) {
        String requestClientId = request.getParameter(CLIENT_ID);
        String requestScope = request.getParameter(SCOPE);
        String jwtPayload = jwsObject.getPayload().toString();
        JSONObject jwtClaims = new JSONObject(jwtPayload);

        String jwtClientId = jwtClaims.optString(CLIENT_ID);
        String jwtScope = jwtClaims.optString(SCOPE);

        if (!requestClientId.equals(jwtClientId) || !requestScope.equals(jwtScope)) {
            throw new RequestMismatchException("OAuth 2.0 parameters do not match the JWT claims.");
        }
    }

    private void validateRedirectUri(String clientId, String redirectUri, JWSObject jwsObject) {
        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            throw new IllegalArgumentException("Client not found for client_id: " + clientId);
        }

        // Validate redirect_uri from JWT if available, else use the provided parameter
        String jwtRedirectUri = jwsObject != null ? jwsObject.getPayload().toJSONObject().get(OAuth2ParameterNames.REDIRECT_URI).toString() : redirectUri;

        if (!registeredClient.getRedirectUris().contains(jwtRedirectUri)) {
            throw new IllegalArgumentException("Invalid redirect_uri: " + jwtRedirectUri);
        }
    }

    private Authentication processAuthorizationFlow(String clientId, String scope, String state, JWSObject jwsObject){
        PublicKey publicKey = didService.getPublicKeyFromDid(clientId);
        jwtService.verifyJWTSignature(jwsObject.serialize(), publicKey, KeyType.EC);

        String signedAuthRequest = jwtService.generateJWT(buildAuthorizationRequestJwtPayload(scope, state));

        cacheStoreForOAuth2AuthorizationRequest.add(state, OAuth2AuthorizationRequest.authorizationCode()
                .state(state)
                .clientId(clientId)
                .redirectUri(jwsObject.getPayload().toJSONObject().get(OAuth2ParameterNames.REDIRECT_URI).toString())
                .scope(scope)
                .authorizationUri(securityProperties.authorizationServer())
                .build());

        String nonce = generateNonce();
        return getAuthentication(state, signedAuthRequest, nonce);
    }

    private Authentication getAuthentication(String state, String signedAuthRequest, String nonce) {
        cacheStoreForAuthorizationRequestJWT.add(nonce, AuthorizationRequestJWT.builder().authRequest(signedAuthRequest).build());

        String authRequest = generateOpenId4VpUrl(nonce);
        String redirectUrl = String.format("/login?authRequest=%s&state=%s",
                URLEncoder.encode(authRequest, StandardCharsets.UTF_8),
                URLEncoder.encode(state, StandardCharsets.UTF_8));

        OAuth2Error error = new OAuth2Error("custom_error", "Redirection required", redirectUrl);
        throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
    }

    private String buildAuthorizationRequestJwtPayload(String scope, String state) {
        // TODO this should be mapped with his presentation definition and return the presentation definition
        // Check and map the scope based on the specific requirement
        if (scope.equals("openid learcredential")) {
            // Map to the specific scope needed for LEAR credentials
            scope = "dome.credentials.presentation.LEARCredentialEmployee";
        } else {
            // If the scope is not supported, throw an exception
            throw new UnsupportedScopeException("Unsupported scope: " + scope);
        }

        Instant issueTime = Instant.now();
        Instant expirationTime = issueTime.plus(10, ChronoUnit.DAYS);

        // Create the JWT claims set with necessary claims
        JWTClaimsSet payload = new JWTClaimsSet.Builder()
                .issuer(cryptoComponent.getECKey().getKeyID())
                .audience(cryptoComponent.getECKey().getKeyID())
                .issueTime(Date.from(issueTime))
                .expirationTime(Date.from(expirationTime))
                .claim("client_id", cryptoComponent.getECKey().getKeyID())
                .claim("client_id_scheme", "did")
                .claim("nonce", generateNonce())
                .claim("response_uri", securityProperties.authorizationServer() + AUTHORIZATION_RESPONSE_ENDPOINT)
                .claim("scope", scope)
                .claim("state", state)
                .claim("response_type", "vp_token")
                .claim("response_mode", "direct_post")
                .build();

        return payload.toString();
    }


    private String generateOpenId4VpUrl(String nonce) {
        String requestUri = String.format("%s/oid4vp/auth-request/%s", securityProperties.authorizationServer(), nonce);
        return String.format("openid4vp://?client_id=%s&request_uri=%s",
                URLEncoder.encode(cryptoComponent.getECKey().getKeyID(), StandardCharsets.UTF_8),
                URLEncoder.encode(requestUri, StandardCharsets.UTF_8));
    }

    private String generateNonce() {
        return UUID.randomUUID().toString();
    }

    private void validateClientId(String clientId) {
        if (clientId == null) {
            throw new IllegalArgumentException("Client ID is required.");
        }
    }
}

