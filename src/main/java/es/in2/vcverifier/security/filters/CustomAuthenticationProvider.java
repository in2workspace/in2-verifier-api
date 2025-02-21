package es.in2.vcverifier.security.filters;

import static es.in2.vcverifier.util.Constants.ACCESS_TOKEN_EXPIRATION_TIME;
import static es.in2.vcverifier.util.Constants.ID_TOKEN_EXPIRATION_TIME;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import es.in2.vcverifier.config.BackendConfig;
import es.in2.vcverifier.config.CacheStore;
import es.in2.vcverifier.exception.InvalidCredentialTypeException;
import es.in2.vcverifier.exception.JsonConversionException;
import es.in2.vcverifier.model.RefreshTokenDataCache;
import es.in2.vcverifier.model.credentials.lear.LEARCredential;
import es.in2.vcverifier.model.credentials.lear.employee.LEARCredentialEmployee;
import es.in2.vcverifier.model.credentials.lear.machine.LEARCredentialMachine;
import es.in2.vcverifier.model.enums.LEARCredentialType;
import es.in2.vcverifier.service.JWTService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.*;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.security.Principal;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

import static org.springframework.security.oauth2.core.oidc.IdTokenClaimNames.NONCE;

@Slf4j
@RequiredArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {
    private final JWTService jwtService;
    private final RegisteredClientRepository registeredClientRepository;
    private final BackendConfig backendConfig;
    private final ObjectMapper objectMapper;
    private final CacheStore<RefreshTokenDataCache> cacheStoreForRefreshTokenData;
    private final OAuth2AuthorizationService oAuth2AuthorizationService;


    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (authentication instanceof OAuth2AuthorizationGrantAuthenticationToken oAuth2AuthorizationGrantAuthenticationToken) {
            log.debug("Authorization token received: {}", oAuth2AuthorizationGrantAuthenticationToken);
            return handleGrant(oAuth2AuthorizationGrantAuthenticationToken);
        }
        log.error("Unsupported grant type: {}", authentication.getClass().getName());
        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNSUPPORTED_GRANT_TYPE);
    }

    private Authentication handleGrant(OAuth2AuthorizationGrantAuthenticationToken authentication) {
        log.info("Processing authorization grant");

        String clientId = getClientId(authentication);
        log.debug("CustomAuthenticationProvider -- handleGrant -- Client ID obtained: {}", clientId);

        RegisteredClient registeredClient = getRegisteredClient(clientId);
        log.debug("CustomAuthenticationProvider -- handleGrant -- Registered client found: {}", registeredClient);

        Instant issueTime = Instant.now();
        Instant expirationTime = issueTime.plus(
                Long.parseLong(ACCESS_TOKEN_EXPIRATION_TIME),
                ChronoUnit.valueOf("MINUTES")
        );
        log.debug("CustomAuthenticationProvider -- handleGrant -- Issue time: {}, Expiration time: {}", issueTime, expirationTime);

        JsonNode credentialJson = getJsonCredential(authentication);
        LEARCredential credential = getVerifiableCredential(authentication, credentialJson);
        String subject = credential.mandateeId();
        log.debug("CustomAuthenticationProvider -- handleGrant -- Credential subject obtained: {}", subject);

        String audience = getAudience(authentication, credential);
        log.debug("CustomAuthenticationProvider -- handleGrant -- Audience for credential: {}", audience);

        String jwtToken = generateAccessTokenWithVc(credential, issueTime, expirationTime, subject, audience);
        log.debug("CustomAuthenticationProvider -- handleGrant -- Generated JWT token: {}", jwtToken);

        OAuth2AccessToken oAuth2AccessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                jwtToken,
                issueTime,
                expirationTime
        );
        OAuth2RefreshToken oAuth2RefreshToken = generateRefreshToken(issueTime);

        String idToken = generateIdToken(credential, subject, audience, authentication.getAdditionalParameters());

        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put("id_token", idToken);

        // Generate the data necessary to be able to refresh the token
        RefreshTokenDataCache refreshTokenDataCache = RefreshTokenDataCache.builder()
                .refreshToken(oAuth2RefreshToken)
                .clientId(clientId)
                .verifiableCredential(credentialJson)
                .build();

        cacheStoreForRefreshTokenData.add(oAuth2RefreshToken.getTokenValue(),refreshTokenDataCache);

        // Save the OAuth2Authorization
        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
                .id(registeredClient.getId())
                .principalName(registeredClient.getClientId())
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .token(oAuth2RefreshToken)
                .attribute(Principal.class.getName(), authentication.getPrincipal())
                .build();
        oAuth2AuthorizationService.save(authorization);

        log.info("Authorization grant successfully processed");
        return new OAuth2AccessTokenAuthenticationToken(registeredClient, authentication, oAuth2AccessToken, oAuth2RefreshToken, additionalParameters);
    }

    private String getClientId(OAuth2AuthorizationGrantAuthenticationToken authentication) {
        // Asumiendo que el clientId puede estar en los parámetros adicionales o como atributo
        Map<String, Object> additionalParameters = authentication.getAdditionalParameters();
        if (additionalParameters != null && additionalParameters.containsKey(OAuth2ParameterNames.CLIENT_ID)) {
            return additionalParameters.get(OAuth2ParameterNames.CLIENT_ID).toString();
        }
        log.error("CustomAuthenticationProvider -- getClientId -- Client ID not found in additional parameters");
        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
    }

    private RegisteredClient getRegisteredClient(String clientId) {
        log.info("Looking up registered client with Client ID: {}", clientId);
        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            log.error("CustomAuthenticationProvider -- getRegisteredClient -- Registered client not found for Client ID: {}", clientId);
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }
        return registeredClient;
    }

    private JsonNode getJsonCredential(OAuth2AuthorizationGrantAuthenticationToken authentication) {
        Map<String, Object> additionalParameters = authentication.getAdditionalParameters();
        if (!additionalParameters.containsKey("vc")) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }
        return objectMapper.convertValue(additionalParameters.get("vc"), JsonNode.class);
    }

    private LEARCredential getVerifiableCredential(OAuth2AuthorizationGrantAuthenticationToken authentication, JsonNode verifiableCredential) {
        if (authentication instanceof OAuth2AuthorizationCodeAuthenticationToken || authentication instanceof OAuth2RefreshTokenAuthenticationToken) {
            return objectMapper.convertValue(verifiableCredential, LEARCredentialEmployee.class);
        } else if (authentication instanceof OAuth2ClientCredentialsAuthenticationToken) {
            return objectMapper.convertValue(verifiableCredential, LEARCredentialMachine.class);
        }

        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
    }

    private String getAudience(OAuth2AuthorizationGrantAuthenticationToken authentication, LEARCredential credential) {
        // Extraer el audience en función del tipo de credencial
        if (credential instanceof LEARCredentialMachine) {
            return backendConfig.getUrl();
        } else if (credential instanceof LEARCredentialEmployee) {
            // Obtener el audience de los parámetros adicionales
            Map<String, Object> additionalParameters = authentication.getAdditionalParameters();
            if (additionalParameters.containsKey(OAuth2ParameterNames.AUDIENCE)) {
                return additionalParameters.get(OAuth2ParameterNames.AUDIENCE).toString();
            } else {
                log.error("CustomAuthenticationProvider -- getAudience -- Parameter 'audience' not found in additional parameters");
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
            }
        }
        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
    }

    private String generateAccessTokenWithVc(LEARCredential learCredential, Instant issueTime, Instant expirationTime, String subject, String audience) {
        log.info("Generating access token with verifiableCredential");

        // Construir el builder del JWTClaimsSet
        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                .issuer(backendConfig.getUrl())
                .audience(audience)
                .subject(subject)
                .jwtID(UUID.randomUUID().toString())
                .issueTime(Date.from(issueTime))
                .expirationTime(Date.from(expirationTime))
                .claim(OAuth2ParameterNames.SCOPE, getScope(learCredential));

        List<String> credentialTypes = learCredential.type();

        if (credentialTypes.contains(LEARCredentialType.LEAR_CREDENTIAL_EMPLOYEE.getValue())) {
            LEARCredentialEmployee credential = (LEARCredentialEmployee) learCredential;
            Map<String, Object> credentialData = objectMapper.convertValue(credential, new TypeReference<>() {});
            claimsBuilder.claim("vc", credentialData);
        } else if (credentialTypes.contains(LEARCredentialType.LEAR_CREDENTIAL_MACHINE.getValue())) {
            LEARCredentialMachine credential = (LEARCredentialMachine) learCredential;
            Map<String, Object> credentialData = objectMapper.convertValue(credential, new TypeReference<>() {});
            claimsBuilder.claim("vc", credentialData);
        } else {
            throw new InvalidCredentialTypeException("Unsupported credential type: " + credentialTypes);
        }

        JWTClaimsSet payload = claimsBuilder.build();

        return jwtService.generateJWT(payload.toString());
    }


    private String generateIdToken(LEARCredential learCredential, String subject, String audience, Map<String, Object> additionalParameters) {
        Instant issueTime = Instant.now();
        Instant expirationTime = issueTime.plus(
                Long.parseLong(ID_TOKEN_EXPIRATION_TIME),
                ChronoUnit.valueOf("MINUTES")
        );

        // Convert the VerifiableCredential to a JSON string
        String verifiableCredentialJson;
        try {
            verifiableCredentialJson = objectMapper.writeValueAsString(learCredential);
        } catch (JsonProcessingException e) {
            throw new JsonConversionException("Error converting Verifiable Credential to JSON: " + e.getMessage());
        }

        // Create the JWT payload (claims) for the ID token
        JWTClaimsSet.Builder idTokenClaimsBuilder = new JWTClaimsSet.Builder()
                .subject(subject)
                .issuer(backendConfig.getUrl())
                .audience(audience)
                .issueTime(Date.from(issueTime))
                .expirationTime(Date.from(expirationTime))
                .claim("auth_time", Date.from(issueTime))
                .claim("acr", "0")
                // Here is used in json format string to be able to save the VC in json format as Keycloak user attribute
                .claim("vc_json", verifiableCredentialJson);

        // Add each additional claim to the ID token
        // Extract additional claims from the verifiable credential
        Map<String, Object> additionalClaims;

        if (additionalParameters.containsKey(OAuth2ParameterNames.SCOPE)) {
            additionalClaims = extractClaimsFromVerifiableCredential(learCredential, additionalParameters);
            additionalClaims.forEach(idTokenClaimsBuilder::claim);
        }

        // This is used only in the authorization code flow
        if (additionalParameters.containsKey(NONCE)) {
            idTokenClaimsBuilder.claim(NONCE, additionalParameters.get(NONCE));
        }

        JWTClaimsSet idTokenClaims = idTokenClaimsBuilder.build();

        // Use JWTService to generate the ID Token (JWT)
        return jwtService.generateJWT(idTokenClaims.toString());
    }

    private OAuth2RefreshToken generateRefreshToken(Instant issueTime) {
        // Generate a random refresh token with at least 128 bits of entropy. Here we use 256 bits (32 bytes)
        SecureRandom secureRandom = new SecureRandom();
        byte[] refreshTokenBytes = new byte[32]; // 256 bits
        secureRandom.nextBytes(refreshTokenBytes);
        String refreshTokenValue = Base64.getUrlEncoder().withoutPadding().encodeToString(refreshTokenBytes);

        // Use the expiration time of the access token to calculate the expiration time of the refresh token
        Instant refreshTokenExpirationTime = issueTime.plus(
                Long.parseLong(ACCESS_TOKEN_EXPIRATION_TIME),
                ChronoUnit.valueOf("MINUTES")
        );
        log.debug("CustomAuthenticationProvider -- generateRefreshToken -- Refresh Token Expiration time: {}", refreshTokenExpirationTime);

        // Create the OAuth2RefreshToken object
        return new OAuth2RefreshToken(refreshTokenValue, issueTime, refreshTokenExpirationTime);
    }


    private Map<String, Object> extractClaimsFromVerifiableCredential(LEARCredential learCredential, Map<String, Object> additionalParameters) {
        Set<String> requestedScopes = new HashSet<>(Arrays.asList(additionalParameters.get(OAuth2ParameterNames.SCOPE).toString().split(" ")));
        Map<String, Object> claims = new HashMap<>();

        if (learCredential instanceof LEARCredentialEmployee learCredentialEmployee) {
            // Check if "profile" scope is requested and add profile-related claims
            if (requestedScopes.contains("profile")) {
                String name = learCredentialEmployee.mandateeFirstName() + " " + learCredentialEmployee.mandateeLastName();
                claims.put("name", name);
                claims.put("given_name", learCredentialEmployee.mandateeFirstName());
                claims.put("family_name", learCredentialEmployee.mandateeLastName());
            }

            // Check if "email" scope is requested and add email-related claims
            if (requestedScopes.contains("email")) {
                claims.put("email", learCredentialEmployee.mandateeEmail());
                claims.put("email_verified", true);
            }
        }
        return claims;
    }


    private String getScope(LEARCredential learCredential) {
        if (learCredential instanceof LEARCredentialEmployee) {
            return "openid learcredential";
        } else if (learCredential instanceof LEARCredentialMachine) {
            return "machine learcredential";
        } else {
            throw new InvalidCredentialTypeException("Credential Type not supported: " + learCredential.getClass().getName());
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2AuthorizationCodeAuthenticationToken.class.isAssignableFrom(authentication)
                || OAuth2ClientCredentialsAuthenticationToken.class.isAssignableFrom(authentication)
                || OAuth2RefreshTokenAuthenticationToken.class.isAssignableFrom(authentication);
    }
}

