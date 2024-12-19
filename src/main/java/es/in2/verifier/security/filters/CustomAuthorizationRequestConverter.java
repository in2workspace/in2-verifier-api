package es.in2.verifier.security.filters;

import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import es.in2.verifier.component.CryptoComponent;
import es.in2.verifier.config.CacheStore;
import es.in2.verifier.config.properties.SecurityProperties;
import es.in2.verifier.model.AuthorizationContext;
import es.in2.verifier.model.AuthorizationRequestJWT;
import es.in2.verifier.service.DIDService;
import es.in2.verifier.service.JWTService;
import io.micrometer.common.util.StringUtils;
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

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

import static es.in2.verifier.util.Constants.*;
import static org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames.NONCE;

@Slf4j
@RequiredArgsConstructor
public class CustomAuthorizationRequestConverter implements AuthenticationConverter {

    private final DIDService didService;
    private final JWTService jwtService;
    private final CryptoComponent cryptoComponent;
    private final CacheStore<AuthorizationRequestJWT> cacheStoreForAuthorizationRequestJWT;
    private final CacheStore<OAuth2AuthorizationRequest> cacheStoreForOAuth2AuthorizationRequest;
    private final SecurityProperties securityProperties;
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

        String originalRequestURL = getFullRequestUrl(request);

        String requestUri = request.getParameter(REQUEST_URI);
        String clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID);
        String state = request.getParameter(OAuth2ParameterNames.STATE);
        String scope = request.getParameter(OAuth2ParameterNames.SCOPE);
        String redirectUri = request.getParameter(OAuth2ParameterNames.REDIRECT_URI);
        String clientNonce = request.getParameter(NONCE);

        AuthorizationContext authorizationContext = AuthorizationContext.builder()
                .requestUri(requestUri)
                .state(state)
                .originalRequestURL(originalRequestURL)
                .redirectUri(redirectUri)
                .clientNonce(clientNonce)
                .scope(scope)
                .build();

        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);

        if (registeredClient == null) {
            log.error("Unauthorized client: Client with ID {} not found.", clientId);
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }

        // Case 1: Authorization request OIDC standard without a signed JWT object
        if (requestUri == null && request.getParameter("request") == null) {
            log.info("Processing an authorization request without a signed JWT object.");
            return handleOIDCStandardRequest(authorizationContext, registeredClient);
        }

        // Case 2: Authorization request following FAPI with a signed JWT object
        return handleFAPIRequest(authorizationContext, request, registeredClient);
    }

    private Authentication handleFAPIRequest(AuthorizationContext authorizationContext, HttpServletRequest request, RegisteredClient registeredClient) {
        String jwt = retrieveJwtFromRequestUriOrRequest(authorizationContext.requestUri(), request, registeredClient, authorizationContext.originalRequestURL());

        // Parse the JWT using the JWTService
        SignedJWT signedJwt = jwtService.parseJWT(jwt);

        // Validate the OAuth 2.0 parameters against JWT claims
        validateOAuth2Parameters(registeredClient, authorizationContext.scope(), signedJwt, authorizationContext.originalRequestURL());

        // Validate the redirect_uri with the client repository
        validateRedirectUri(registeredClient, authorizationContext.redirectUri(), signedJwt, authorizationContext.originalRequestURL());

        // Validate the nonce for the FAPI scenario
        validateNonceRequired(authorizationContext.clientNonce(), registeredClient, authorizationContext.originalRequestURL());

        // Process the authorization flow
        return processAuthorizationFlow(authorizationContext, signedJwt, registeredClient);
    }

    /**
     * Handle authorization requests without a signed JWT object.
     */
    private Authentication handleOIDCStandardRequest(AuthorizationContext authorizationContext, RegisteredClient registeredClient) {
        // Validate redirect_uri for non-signed requests
        validateRedirectUri(registeredClient, authorizationContext.redirectUri(), null, authorizationContext.originalRequestURL());

        // Validate client nonce for non-signed requests
        validateNonceRequired(authorizationContext.clientNonce(), registeredClient, authorizationContext.originalRequestURL());

        // Cache the OAuth2 authorization request
        cacheAuthorizationRequest(authorizationContext, registeredClient.getClientId(), authorizationContext.redirectUri());

        String nonce = generateNonce();
        String signedAuthRequest = jwtService.generateJWT(buildAuthorizationRequestJwtPayload(registeredClient, authorizationContext.scope(), authorizationContext.state(), authorizationContext.originalRequestURL()));

        return getAuthentication(authorizationContext.state(), signedAuthRequest, nonce, registeredClient);
    }

    private void throwInvalidClientAuthenticationException(String errorMessage, String clientName, String errorCode, String originalRequestURL) {
        String redirectUrl = String.format(CLIENT_ERROR_ENDPOINT + "?errorCode=%s&errorMessage=%s&clientUrl=%s&originalRequestURL=%s",
                URLEncoder.encode(errorCode, StandardCharsets.UTF_8),
                URLEncoder.encode(errorMessage, StandardCharsets.UTF_8),
                URLEncoder.encode(clientName, StandardCharsets.UTF_8),
                URLEncoder.encode(originalRequestURL, StandardCharsets.UTF_8));
        OAuth2Error error = new OAuth2Error("invalid_client_authentication", errorMessage, redirectUrl);
        throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
    }

    /**
     * Retrieve JWT from either request_uri or request parameter.
     */
    private String retrieveJwtFromRequestUriOrRequest(String requestUri, HttpServletRequest request, RegisteredClient registeredClient, String originalRequestURL) {
        if (requestUri != null) {
            try {
                log.info("Retrieving JWT from request_uri: {}", requestUri);
                // Retrieve the JWT from the request_uri via HTTP GET
                HttpClient client = HttpClient.newHttpClient();
                HttpRequest httpRequest = HttpRequest.newBuilder()
                        .uri(URI.create(requestUri))
                        .GET()
                        .build();
                HttpResponse<String> httpResponse = client.send(httpRequest, HttpResponse.BodyHandlers.ofString());

                // **Aquí agregamos la validación del estado y el cuerpo**
                if (httpResponse.statusCode() != 200 || StringUtils.isBlank(httpResponse.body())) {
                    String errorCode = generateNonce();
                    String errorMessage = "Failed to retrieve JWT from request_uri: Invalid response.";
                    log.error(LOG_ERROR_FORMAT, errorCode, errorMessage);
                    throwInvalidClientAuthenticationException(errorMessage, registeredClient.getClientName(), errorCode, originalRequestURL);
                }

                log.debug("JWT successfully retrieved from request_uri.");
                return httpResponse.body();
            } catch (IOException | InterruptedException e) {
                String errorCode = generateNonce();
                String errorMessage = "Failed to retrieve JWT from request_uri.";
                log.error(LOG_ERROR_FORMAT, errorCode, errorMessage, e);
                Thread.currentThread().interrupt();
                throwInvalidClientAuthenticationException(errorMessage, registeredClient.getClientName(), errorCode, originalRequestURL);
            }
        }
        return request.getParameter("request");
    }

    /**
     * Validate OAuth2 parameters and compare them with JWT claims.
     */
    private void validateOAuth2Parameters(RegisteredClient registeredClient, String scope, SignedJWT signedJwt, String originalRequestURL) {
        String clientId = registeredClient.getClientId();
        Payload payload = signedJwt.getPayload();
        String jwtClientId = jwtService.getClaimFromPayload(payload, CLIENT_ID);
        String jwtScope = jwtService.getClaimFromPayload(payload, SCOPE);

        if (!clientId.equals(jwtClientId) || !scope.equals(jwtScope)) {
            String errorCode = generateNonce();
            String errorMessage = "The OAuth 2.0 parameters do not match the JWT claims.";
            log.error(LOG_ERROR_FORMAT, errorCode, errorMessage);
            throwInvalidClientAuthenticationException(errorMessage,registeredClient.getClientName(), errorCode, originalRequestURL);
        }
    }

    /**
     * Validate the redirect_uri with the registered client repository.
     */
    private void validateRedirectUri(RegisteredClient registeredClient, String redirectUri, SignedJWT signedJwt, String originalRequestURL) {
        String jwtRedirectUri = signedJwt != null ? jwtService.getClaimFromPayload(signedJwt.getPayload(), OAuth2ParameterNames.REDIRECT_URI) : redirectUri;

        if (!registeredClient.getRedirectUris().contains(jwtRedirectUri)) {
            String errorCode = generateNonce();
            String errorMessage = "The redirect_uri does not match any of the registered client's redirect_uris.";
            log.error(LOG_ERROR_FORMAT, errorCode, errorMessage);
            throwInvalidClientAuthenticationException(errorMessage, registeredClient.getClientName(), errorCode, originalRequestURL);
        }
    }

    private void validateNonceRequired(String clientNonce, RegisteredClient registeredClient, String originalRequestURL) {
        if (StringUtils.isBlank(clientNonce)) {
            String errorCode = generateNonce();
            String errorMessage = "The 'nonce' parameter is required but is missing.";
            log.error(LOG_ERROR_FORMAT, errorCode, errorMessage);
            throwInvalidClientAuthenticationException(errorMessage, registeredClient.getClientName(), errorCode, originalRequestURL);
        }
    }

    private Authentication processAuthorizationFlow(AuthorizationContext authorizationContext, SignedJWT signedJwt, RegisteredClient registeredClient) {
        PublicKey publicKey = didService.getPublicKeyFromDid(registeredClient.getClientId());
        jwtService.verifyJWTWithECKey(signedJwt.serialize(), publicKey);

        String signedAuthRequest = jwtService.generateJWT(buildAuthorizationRequestJwtPayload(registeredClient, authorizationContext.scope(), authorizationContext.state(), authorizationContext.originalRequestURL()));

        cacheAuthorizationRequest(authorizationContext, registeredClient.getClientId(), jwtService.getClaimFromPayload(signedJwt.getPayload(), OAuth2ParameterNames.REDIRECT_URI));

        String nonce = generateNonce();
        return getAuthentication(authorizationContext.state(), signedAuthRequest, nonce, registeredClient);
    }

    private Authentication getAuthentication(String state, String signedAuthRequest, String nonce, RegisteredClient registeredClient) {
        cacheStoreForAuthorizationRequestJWT.add(nonce, AuthorizationRequestJWT.builder().authRequest(signedAuthRequest).build());

        // This is used to allow the user to return to the application if the user wants to cancel the login
        String homeUri = registeredClient.getClientName();

        String authRequest = generateOpenId4VpUrl(nonce);
        String redirectUrl = String.format(LOGIN_ENDPOINT + "?authRequest=%s&state=%s&homeUri=%s",
                URLEncoder.encode(authRequest, StandardCharsets.UTF_8),
                URLEncoder.encode(state, StandardCharsets.UTF_8),
                URLEncoder.encode(homeUri, StandardCharsets.UTF_8));

        OAuth2Error error = new OAuth2Error(REQUIRED_EXTERNAL_USER_AUTHENTICATION, "Redirection required", redirectUrl);
        throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
    }

    private String buildAuthorizationRequestJwtPayload(RegisteredClient registeredClient, String scope, String state, String originalRequestURL) {
        // TODO: Map the scope with its presentation definition and return the presentation definition
        // Check and map the scope based on the specific requirement
        checkAuthorizationRequestScope(scope, registeredClient, originalRequestURL);

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
                .claim(OAuth2ParameterNames.SCOPE, "dome.credentials.presentation.LEARCredentialEmployee")
                .claim(OAuth2ParameterNames.STATE, state)
                .claim(OAuth2ParameterNames.RESPONSE_TYPE, "vp_token")
                .claim("response_mode", "direct_post")
                .jwtID(UUID.randomUUID().toString())
                .build();

        return payload.toString();
    }

    private void checkAuthorizationRequestScope(String scope, RegisteredClient registeredClient, String originalRequestURL) {
        if (!scope.contains("learcredential")) {
            String errorCode = generateNonce();
            String errorMessage = "The requested scope does not contain 'learcredential'. Currently, we only support this scope and 'email', 'profile' as optional.";
            log.error(LOG_ERROR_FORMAT, errorCode, errorMessage);
            throwInvalidClientAuthenticationException(errorMessage, registeredClient.getClientName(), errorCode, originalRequestURL);
        }
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

    private void cacheAuthorizationRequest(AuthorizationContext authorizationContext, String clientId, String redirectUri) {
        OAuth2AuthorizationRequest oAuth2AuthorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
                .state(authorizationContext.state())
                .clientId(clientId)
                .redirectUri(redirectUri)
                .scope(authorizationContext.scope())
                .authorizationUri(securityProperties.authorizationServer())
                .additionalParameters(Map.of(NONCE, authorizationContext.clientNonce()))
                .build();

        cacheStoreForOAuth2AuthorizationRequest.add(authorizationContext.state(), oAuth2AuthorizationRequest);
    }

    private String getFullRequestUrl(HttpServletRequest request) {
        StringBuilder requestURL = new StringBuilder(request.getRequestURL());
        String queryString = request.getQueryString();

        if (queryString != null) {
            requestURL.append('?').append(queryString);
        }

        return requestURL.toString();
    }


}
