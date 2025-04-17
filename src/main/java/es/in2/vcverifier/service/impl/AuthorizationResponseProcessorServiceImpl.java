package es.in2.vcverifier.service.impl;

import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.config.BackendConfig;
import es.in2.vcverifier.config.CacheStore;
import es.in2.vcverifier.exception.InvalidVPtokenException;
import es.in2.vcverifier.exception.JWTClaimMissingException;
import es.in2.vcverifier.exception.JWTParsingException;
import es.in2.vcverifier.exception.LoginTimeoutException;
import es.in2.vcverifier.model.AuthorizationCodeData;
import es.in2.vcverifier.service.AuthorizationResponseProcessorService;
import es.in2.vcverifier.service.VpService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;
import static es.in2.vcverifier.util.Constants.EXPIRATION;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import static es.in2.vcverifier.util.Constants.*;
import static org.springframework.security.oauth2.core.oidc.IdTokenClaimNames.NONCE;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthorizationResponseProcessorServiceImpl implements AuthorizationResponseProcessorService {

    private final CacheStore<OAuth2AuthorizationRequest> cacheStoreForOAuth2AuthorizationRequest;
    private final CacheStore<AuthorizationCodeData> cacheStoreForAuthorizationCodeData;
    private final VpService vpService; // Service responsible for VP validation
    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationService oAuth2AuthorizationService;
    private final SimpMessagingTemplate messagingTemplate;
    private final BackendConfig backendConfig;
    private final CacheStore<String> cacheForNonceByState;

    @Override
    public void processAuthResponse(String state, String vpToken){
        log.info("Processing authorization response");

        // Validate if the state exists in the cache
        OAuth2AuthorizationRequest oAuth2AuthorizationRequest = cacheStoreForOAuth2AuthorizationRequest.get(state);

        // Remove the state from cache after retrieving the Object
        cacheStoreForOAuth2AuthorizationRequest.delete(state);

        Instant issueTime = Instant.now();

        Object expirationLoginValue = oAuth2AuthorizationRequest.getAdditionalParameters().get(EXPIRATION);

        if(expirationLoginValue==null){
            throw new LoginTimeoutException("Start time is missing from login request");
        }

        if (issueTime.getEpochSecond() >= (long) expirationLoginValue) {
            throw new LoginTimeoutException("Login time has expired");
        }
        String redirectUri = oAuth2AuthorizationRequest.getRedirectUri();
        // Decode vpToken from Base64
        String decodedVpToken = new String(Base64.getDecoder().decode(vpToken), StandardCharsets.UTF_8);
        log.info("Decoded VP Token: {}", decodedVpToken);

        validateVpAudience(decodedVpToken);
        // Send the decoded token to a service for validation
        boolean isValid = vpService.validateVerifiablePresentation(decodedVpToken);
        if (!isValid) {
            log.error("VP Token is invalid");
            throw new InvalidVPtokenException("VP Token used in H2M flow is invalid");
        }
        log.info("VP Token validated successfully");

        // Generate a code (code)
        String code = UUID.randomUUID().toString();
        log.info("Code generated: {}", code);

        RegisteredClient registeredClient = registeredClientRepository.findByClientId(oAuth2AuthorizationRequest.getClientId());

        if (registeredClient == null) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }

        Instant expirationTime = issueTime.plus(Long.parseLong(ACCESS_TOKEN_EXPIRATION_TIME), ChronoUnit.valueOf(ACCESS_TOKEN_EXPIRATION_CHRONO_UNIT));
        // Register the Oauth2Authorization because is needed for verifications
        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
                .id(registeredClient.getId())
                .principalName(registeredClient.getClientId())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .token(new OAuth2AuthorizationCode(code, issueTime, expirationTime))
                .attribute(OAuth2AuthorizationRequest.class.getName(), oAuth2AuthorizationRequest)
                .build();

        log.info("OAuth2Authorization generated");

        // Retrieve nonce from additional parameters
        String nonceValue = (String) oAuth2AuthorizationRequest.getAdditionalParameters().get(NONCE);

        // Create a builder
        AuthorizationCodeData.AuthorizationCodeDataBuilder authCodeDataBuilder = AuthorizationCodeData.builder()
                .state(state)
                .verifiableCredential(vpService.getCredentialFromTheVerifiablePresentationAsJsonNode(decodedVpToken))
                .oAuth2Authorization(authorization)
                .requestedScopes(oAuth2AuthorizationRequest.getScopes());

        // Conditionally add the nonce if it's not null or blank
        validateVpNonce(nonceValue, state);
        authCodeDataBuilder.clientNonce(nonceValue);

        // Finally build the object
        AuthorizationCodeData authorizationCodeData = authCodeDataBuilder.build();
        cacheStoreForAuthorizationCodeData.add(code, authorizationCodeData);

        oAuth2AuthorizationService.save(authorization);

        // Build the redirect URL with the code (code) and the state
        String redirectUrl = UriComponentsBuilder.fromHttpUrl(redirectUri)
                .queryParam("code", code)
                .queryParam("state", state)
                .build()
                .toUriString();

        //Perform the redirection using HttpServletResponse
        log.info("Redirecting to URL: {}", redirectUrl);

        // Enviar la URL de redirección al cliente a través del WebSocket
        messagingTemplate.convertAndSend("/oidc/redirection/" + state, redirectUrl);

    }


    private void validateVpNonce(String vpNonce,String state) {
        if (vpNonce == null || vpNonce.isBlank()) {
            throw new JWTClaimMissingException("The 'nonce' claim is missing in the VP token.");
        }
        if (state == null || state.isBlank()) {
            throw new JWTClaimMissingException("The 'state' claim is missing in the VP token.");
        }
        String cachedNonce = cacheForNonceByState.get(state);
        if (cachedNonce == null) {
            throw new JWTClaimMissingException("No nonce found in cache for state=" + state);
        }
        if (!vpNonce.equals(cachedNonce)) {
            throw new JWTClaimMissingException("VP nonce does not match the cached nonce for the given state.");
        }
        log.debug("Validating VP nonce: received={}, cached={}", vpNonce, cachedNonce);
    }

    private void validateVpAudience(String decodedVpToken) {
        try {
            SignedJWT vpSignedJWT = SignedJWT.parse(decodedVpToken);
            List<String> audiences = vpSignedJWT.getJWTClaimsSet().getAudience();
            if (audiences == null || audiences.isEmpty()) {
                throw new JWTClaimMissingException("The 'aud' claim is missing in the VP token.");
            }
            String expectedAudience = backendConfig.getUrl();
            if (!audiences.contains(expectedAudience)) {
                throw new JWTClaimMissingException("The 'aud' claim in the VP token does not match the expected verifier URL.");
            }
        } catch (ParseException e) {
            throw new JWTParsingException("Failed to parse the VP JWT while validating the 'aud' claim.");
        }
    }
}


