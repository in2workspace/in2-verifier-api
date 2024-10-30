package es.in2.vcverifier.security.filters;

import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.component.CryptoComponent;
import es.in2.vcverifier.config.CacheStore;
import es.in2.vcverifier.config.properties.SecurityProperties;
import es.in2.vcverifier.exception.RequestMismatchException;
import es.in2.vcverifier.exception.UnsupportedScopeException;
import es.in2.vcverifier.model.AuthorizationRequestJWT;
import es.in2.vcverifier.model.enums.KeyType;
import es.in2.vcverifier.service.DIDService;
import es.in2.vcverifier.service.HttpClientService;
import es.in2.vcverifier.service.JWTService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
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
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Map;
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

    /**
     * The Authorization Request MUST be signed by the Client, and MUST use the request_uri parameter which enables
     * the request to be passed by reference, as described in section 6.2. Passing a Request Object by Reference of
     * the OpenID Connect spec. The request_uri value is a URL referencing a resource containing a Request Object
     * value, which is a JWT containing the request parameters. This URL MUST use the https scheme.
     *
     * @param request - The HttpServletRequest
     * @return - The Authentication object
     */
    @Override
    public Authentication convert(HttpServletRequest request) {
        log.info("CustomAuthorizationRequestConverter.convert");

        String requestUri = request.getParameter(REQUEST_URI);
        String jwt;
        String clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID);
        String state = request.getParameter(OAuth2ParameterNames.STATE);
        String clientNonce = request.getParameter(NONCE);
        String scope = request.getParameter(OAuth2ParameterNames.SCOPE);
        String redirectUri = request.getParameter(OAuth2ParameterNames.REDIRECT_URI);

        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);

        if (registeredClient == null) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }

        // Check for required client ID
        validateClientId(clientId);

        // Case 1: No 'request' or 'request_uri' is provided, assuming it's an authorization request without a signed object
        if (requestUri == null && request.getParameter("request") == null) {
            log.info("Processing an authorization request without a signed JWT object.");
            return handleNonSignedAuthorizationRequest(clientId, state, scope, redirectUri, clientNonce, registeredClient);
        }

        // Case 2: JWT present via either 'request_uri' or 'request' parameters
        jwt = retrieveJwtFromRequestUriOrRequest(requestUri, request);

        // Parse the JWT using the JWTService
        SignedJWT signedJwt = jwtService.parseJWT(jwt);

        // Step 3: Validate the OAuth 2.0 parameters against JWT claims
        validateOAuth2Parameters(request, signedJwt);

        // Step 4: Validate the redirect_uri with the client repository
        validateRedirectUri(clientId, redirectUri, signedJwt);

        // Step 5: Process the authorization flow
        return processAuthorizationFlow(clientId, scope, state, signedJwt, clientNonce, registeredClient);

    }

    /**
     * Handle authorization requests without a signed JWT object.
     */
    private Authentication handleNonSignedAuthorizationRequest(String clientId, String state, String scope, String redirectUri, String clientNonce, RegisteredClient registeredClient) {
        // Validate redirect_uri for non-signed requests
        validateRedirectUri(clientId, redirectUri, null);

        // Cache the OAuth2 authorization request
        cacheStoreForOAuth2AuthorizationRequest.add(state, OAuth2AuthorizationRequest.authorizationCode()
                .state(state)
                .clientId(clientId)
                .redirectUri(redirectUri)
                .scope(scope)
                .authorizationUri(securityProperties.authorizationServer())
                .additionalParameters(Map.of(NONCE, clientNonce))
                .build());

        String nonce = generateNonce();
        String signedAuthRequest = jwtService.generateJWT(buildAuthorizationRequestJwtPayload(scope, state));

        return getAuthentication(state, signedAuthRequest, nonce, registeredClient);
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

    /**
     * Validate OAuth2 parameters and compare them with JWT claims.
     */
    private void validateOAuth2Parameters(HttpServletRequest request, SignedJWT signedJwt) {
        String requestClientId = request.getParameter(CLIENT_ID);
        String requestScope = request.getParameter(SCOPE);
        Payload payload = signedJwt.getPayload();

        String jwtClientId = jwtService.getClaimFromPayload(payload, CLIENT_ID);
        String jwtScope = jwtService.getClaimFromPayload(payload, SCOPE);

        if (!requestClientId.equals(jwtClientId) || !requestScope.equals(jwtScope)) {
            throw new RequestMismatchException("OAuth 2.0 parameters do not match the JWT claims.");
        }
    }

    /**
     * Validate the redirect_uri with the registered client repository.
     */
    private void validateRedirectUri(String clientId, String redirectUri, SignedJWT signedJwt) {
        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            throw new IllegalArgumentException("Client not found for client_id: " + clientId);
        }

        String jwtRedirectUri = signedJwt != null ? jwtService.getClaimFromPayload(signedJwt.getPayload(), OAuth2ParameterNames.REDIRECT_URI) : redirectUri;

        if (!registeredClient.getRedirectUris().contains(jwtRedirectUri)) {
            throw new IllegalArgumentException("Invalid redirect_uri: " + jwtRedirectUri);
        }
    }

    private Authentication processAuthorizationFlow(String clientId, String scope, String state, SignedJWT signedJwt, String clientNonce, RegisteredClient registeredClient) {
        PublicKey publicKey = didService.getPublicKeyFromDid(clientId);
        jwtService.verifyJWTSignature(signedJwt.serialize(), publicKey, KeyType.EC);

        String signedAuthRequest = jwtService.generateJWT(buildAuthorizationRequestJwtPayload(scope, state));

        cacheStoreForOAuth2AuthorizationRequest.add(state, OAuth2AuthorizationRequest.authorizationCode()
                .state(state)
                .clientId(clientId)
                .redirectUri(jwtService.getClaimFromPayload(signedJwt.getPayload(), OAuth2ParameterNames.REDIRECT_URI))
                .scope(scope)
                .authorizationUri(securityProperties.authorizationServer())
                .additionalParameters(Map.of(NONCE, clientNonce))
                .build());

        String nonce = generateNonce();
        return getAuthentication(state, signedAuthRequest, nonce, registeredClient);
    }

    private Authentication getAuthentication(String state, String signedAuthRequest, String nonce, RegisteredClient registeredClient) {
        cacheStoreForAuthorizationRequestJWT.add(nonce, AuthorizationRequestJWT.builder().authRequest(signedAuthRequest).build());

        // This is used to allow the user te return to the application if the user wants to cancel the login
        String homeUri = registeredClient.getClientName();

        String authRequest = generateOpenId4VpUrl(nonce);
        String redirectUrl = String.format("/login?authRequest=%s&state=%s&homeUri=%s",
                URLEncoder.encode(authRequest, StandardCharsets.UTF_8),
                URLEncoder.encode(state, StandardCharsets.UTF_8),
                URLEncoder.encode(homeUri, StandardCharsets.UTF_8));

        OAuth2Error error = new OAuth2Error("custom_error", "Redirection required", redirectUrl);
        throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
    }

    private String buildAuthorizationRequestJwtPayload(String scope, String state) {
        // TODO this should be mapped with his presentation definition and return the presentation definition
        // Check and map the scope based on the specific requirement
        if ("openid learcredential".equals(scope)) {
            scope = "dome.credentials.presentation.LEARCredentialEmployee";
        } else {
            throw new UnsupportedScopeException("Unsupported scope: " + scope);
        }

        Instant issueTime = Instant.now();
        Instant expirationTime = issueTime.plus(10, ChronoUnit.DAYS);

        JWTClaimsSet payload = new JWTClaimsSet.Builder()
                .issuer(cryptoComponent.getECKey().getKeyID())
                .audience(cryptoComponent.getECKey().getKeyID())
                .issueTime(Date.from(issueTime))
                .expirationTime(Date.from(expirationTime))
                .claim(OAuth2ParameterNames.CLIENT_ID, cryptoComponent.getECKey().getKeyID())
                .claim("client_id_scheme", "did")
                .claim(NONCE, generateNonce())
                .claim("response_uri", securityProperties.authorizationServer() + AUTHORIZATION_RESPONSE_ENDPOINT)
                .claim(OAuth2ParameterNames.SCOPE, scope)
                .claim(OAuth2ParameterNames.STATE, state)
                .claim(OAuth2ParameterNames.RESPONSE_TYPE, "vp_token")
                .claim("response_mode", "direct_post")
                .jwtID(UUID.randomUUID().toString())
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

