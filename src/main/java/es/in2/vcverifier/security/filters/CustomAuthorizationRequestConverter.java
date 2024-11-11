package es.in2.vcverifier.security.filters;

import com.nimbusds.jose.JWSObject;
import com.nimbusds.jwt.JWTClaimsSet;
import es.in2.vcverifier.component.CryptoComponent;
import es.in2.vcverifier.config.CacheStore;
import es.in2.vcverifier.config.properties.SecurityProperties;
import es.in2.vcverifier.exception.JWTParsingException;
import es.in2.vcverifier.exception.RequestMismatchException;
import es.in2.vcverifier.exception.RequestObjectRetrievalException;
import es.in2.vcverifier.exception.UnsupportedScopeException;
import es.in2.vcverifier.model.AuthorizationRequestJWT;
import es.in2.vcverifier.model.enums.KeyType;
import es.in2.vcverifier.service.DIDService;
import es.in2.vcverifier.service.JWTService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
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
        String requestUri = request.getParameter(REQUEST_URI); // request_uri parameter
        String jwt;     // request parameter (JWT directly)
        String clientId = request.getParameter(CLIENT_ID);     // client_id parameter
        String state = request.getParameter("state");
        String scope = request.getParameter(SCOPE);

        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);

        if (registeredClient == null) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }

        if (clientId == null) {
            throw new IllegalArgumentException("Client ID is required.");
        }

        // Case 1: JWT needs to be retrieved via "request_uri"
        if (requestUri != null) {
            log.info("Retrieving JWT from request_uri: " + requestUri);
            // Retrieve the JWT from the request_uri via HTTP GET
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest httpRequest = HttpRequest.newBuilder()
                    .uri(URI.create(requestUri))
                    .GET()
                    .build();
            HttpResponse<String> httpResponse;
            try {
                httpResponse = client.send(httpRequest, HttpResponse.BodyHandlers.ofString());
                jwt = httpResponse.body(); // Set the JWT from the HTTP response body
            } catch (IOException | InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new RequestObjectRetrievalException(e.getMessage());
            }
        } else {
            // If neither request nor request_uri is provided, throw an exception
            throw new IllegalArgumentException("Either 'request' or 'request_uri' must be provided.");
        }
        // Validate the JWT and create a custom authentication token
        try {
            JWSObject jwsObject = JWSObject.parse(jwt);
            // Validate OAuth 2.0 parameters against the JWT
            if (!validateOAuth2Parameters(request, jwsObject)) {
                throw new RequestMismatchException("OAuth 2.0 parameters do not match the JWT claims.");
            }
            // Use DIDService to get the public key bytes
            PublicKey publicKey = didService.getPublicKeyFromDid(clientId);
            // Use JWTService to verify the JWT signature
            jwtService.verifyJWTSignature(jwt, publicKey, KeyType.EC);
            String signedAuthRequest = jwtService.generateJWT(buildAuthorizationRequestJwtPayload(scope, state));
            cacheStoreForOAuth2AuthorizationRequest.add(state, OAuth2AuthorizationRequest.authorizationCode()
                    .state(state)
                    .clientId(clientId)
                    .redirectUri(jwsObject.getPayload().toJSONObject().get("redirect_uri").toString())
                    .scope(scope)
                    .authorizationUri(securityProperties.authorizationServer())
                    .build()
            );
            String nonce = generateNonce();
            cacheStoreForAuthorizationRequestJWT.add(nonce,AuthorizationRequestJWT.builder()
                    .authRequest(signedAuthRequest)
                    .build()
            );

            // This is used to allow the user te return to the application if the user wants to cancel the login
            String homeUri = registeredClient.getClientName();

            String authRequest = generateOpenId4VpUrl(nonce);
            String redirectUrl = String.format("/login?authRequest=%s&state=%s&homeUri=%s",
                    URLEncoder.encode(authRequest, StandardCharsets.UTF_8),
                    URLEncoder.encode(state, StandardCharsets.UTF_8),
                    URLEncoder.encode(homeUri, StandardCharsets.UTF_8));
            OAuth2Error error = new OAuth2Error("custom_error", "Redirection required", redirectUrl);
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(error,null);
        } catch (ParseException e) {
            throw new RequestObjectRetrievalException(e.getMessage());
        }
    }

    private boolean validateOAuth2Parameters(HttpServletRequest request, JWSObject jwsObject) {
        try {
            String jwtPayload = jwsObject.getPayload().toString();
            JSONObject jwtClaims = new JSONObject(jwtPayload);
            String requestResponseType = request.getParameter(RESPONSE_TYPE);
            String requestClientId = request.getParameter(CLIENT_ID);
            String requestScope = request.getParameter(SCOPE);
            String jwtResponseType = jwtClaims.optString(RESPONSE_TYPE);
            String jwtClientId = jwtClaims.optString(CLIENT_ID);
            String jwtScope = jwtClaims.optString(SCOPE);

            // Ensure that required OAuth 2.0 parameters match those in the JWT
            return requestResponseType.equals(jwtResponseType)
                    && requestClientId.equals(jwtClientId)
                    && requestScope.contains("openid")
                    && requestScope.equals(jwtScope);
        } catch (JSONException e) {
            throw new JWTParsingException("Invalid JWT payload " + e.getMessage());
        }
    }

    private String buildAuthorizationRequestJwtPayload(String scope, String state) {
        // TODO this should be mapped with his presentation definition and return the presentation definition
        if (scope.equals("openid_learcredential")){
            scope = "dome.credentials.presentation.LEARCredentialEmployee";
        }
        else {
            throw new UnsupportedScopeException("Unsupported scope");
        }
        Instant issueTime = Instant.now();
        Instant expirationTime = issueTime.plus(10, ChronoUnit.DAYS);
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

}
