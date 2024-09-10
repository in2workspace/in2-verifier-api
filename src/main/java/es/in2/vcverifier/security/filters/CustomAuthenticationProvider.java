package es.in2.vcverifier.security.filters;

import com.nimbusds.jwt.JWTClaimsSet;
import es.in2.vcverifier.config.CacheStore;
import es.in2.vcverifier.crypto.CryptoComponent;
import es.in2.vcverifier.exception.UnsupportedScopeException;
import es.in2.vcverifier.model.AuthorizationRequest;
import es.in2.vcverifier.service.AuthenticationService;
import es.in2.vcverifier.service.JWTService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationConsentAuthenticationToken;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static es.in2.vcverifier.util.Constants.AUTHORIZATION_RESPONSE_ENDPOINT;

@RequiredArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {
    private final CryptoComponent cryptoComponent;
    private final JWTService jwtService;
    private final CacheStore<String> cacheStoreForRedirectUri;  // Cache para guardar state -> redirect_uri del OAuth2AuthorizationCodeRequestAuthenticationToken
    private final CacheStore<String> cacheStoreForJwt;  // Cache para guardar state -> JWT
    private final AuthenticationService authenticationService;


    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (authentication instanceof OAuth2AuthorizationCodeRequestAuthenticationToken oAuth2AuthorizationCodeRequestAuthenticationToken) {
            // Procesa la autenticación personalizada
            // Verifica la validez del request_uri y otros parámetros necesarios
            // Retorna un objeto Authentication si es exitoso
            String signedAuthRequest = jwtService.generateJWT(buildAuthorizationRequestJwtPayload(oAuth2AuthorizationCodeRequestAuthenticationToken));

            cacheStoreForRedirectUri.add(oAuth2AuthorizationCodeRequestAuthenticationToken.getState(), oAuth2AuthorizationCodeRequestAuthenticationToken.getRedirectUri());

            String nonce = generateNonce();

            cacheStoreForJwt.add(nonce,signedAuthRequest);

            String authRequest = generateOpenId4VpUrl(nonce);

            // Crear el mapa de parámetros adicionales y agregar el authRequest
            Map<String, Object> additionalParameters = new HashMap<>();
            additionalParameters.put("authorizationRequest", authRequest);

            return new OAuth2AuthorizationConsentAuthenticationToken(
                    oAuth2AuthorizationCodeRequestAuthenticationToken.getAuthorizationUri(),
                    oAuth2AuthorizationCodeRequestAuthenticationToken.getClientId(),
                    authenticationService.createAuthentication(oAuth2AuthorizationCodeRequestAuthenticationToken.getClientId()),
                    oAuth2AuthorizationCodeRequestAuthenticationToken.getState(),
                    oAuth2AuthorizationCodeRequestAuthenticationToken.getScopes(),
                    additionalParameters
            );
        }
        else {
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(
                new OAuth2Error(
                        "invalid_request",
                        "The request is missing a required parameter",
                        null),
                null
            );
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2AuthorizationCodeRequestAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private String buildAuthorizationRequestJwtPayload(OAuth2AuthorizationCodeRequestAuthenticationToken authToken) {
        String scope;

        if (authToken.getScopes().contains("openid_learcredential")){
            scope = "dome.credentials.presentation.LEARCredentialEmployee";
        }
        else {
            throw new UnsupportedScopeException("Unsupported scope");
        }
        Instant issueTime = Instant.now();
        Instant expirationTime = issueTime.plus(10, ChronoUnit.DAYS);
        JWTClaimsSet payload = new JWTClaimsSet.Builder()
                .issuer(cryptoComponent.getECKey().getKeyID())
                .issueTime(Date.from(issueTime))
                .expirationTime(Date.from(expirationTime))
                .claim("client_id", cryptoComponent.getECKey().getKeyID())
                .claim("client_id_scheme", "did")
                .claim("nonce", generateNonce())
                .claim("response_uri", AUTHORIZATION_RESPONSE_ENDPOINT)
                .claim("scope", scope)
                .claim("state", authToken.getState())
                .claim("response_type", "vp_token")
                .claim("response_mode", "direct_post")
                .build();
        return payload.toString();
    }

    private String generateOpenId4VpUrl(String nonce) {
        String requestUri = String.format("http://localhost:9000/oid4vp/auth-request/%s", nonce);

        return String.format("openid4vp://?client_id=%s&request_uri=%s",
                URLEncoder.encode(cryptoComponent.getECKey().getKeyID(), StandardCharsets.UTF_8),
                URLEncoder.encode(requestUri, StandardCharsets.UTF_8));
    }

    private String generateNonce() {
        return UUID.randomUUID().toString();
    }

}