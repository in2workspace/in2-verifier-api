package es.in2.verifier.security.filters;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import es.in2.verifier.config.properties.SecurityProperties;
import es.in2.verifier.exception.InvalidCredentialTypeException;
import es.in2.verifier.exception.JsonConversionException;
import es.in2.verifier.model.credentials.lear.LEARCredential;
import es.in2.verifier.model.credentials.lear.employee.LEARCredentialEmployee;
import es.in2.verifier.model.credentials.lear.machine.LEARCredentialMachine;
import es.in2.verifier.model.enums.LEARCredentialType;
import es.in2.verifier.service.JWTService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

@Slf4j
@RequiredArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {
    private final JWTService jwtService;
    private final RegisteredClientRepository registeredClientRepository;
    private final SecurityProperties securityProperties;
    private final ObjectMapper objectMapper;

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
                Long.parseLong(securityProperties.token().accessToken().expiration()),
                ChronoUnit.valueOf(securityProperties.token().accessToken().cronUnit())
        );
        log.debug("CustomAuthenticationProvider -- handleGrant -- Issue time: {}, Expiration time: {}", issueTime, expirationTime);

        LEARCredential credential = getVerifiableCredential(authentication);
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

        String idToken = generateIdToken(credential, subject, audience, authentication.getAdditionalParameters());

        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put("id_token", idToken);

        log.info("Authorization grant successfully processed");
        return new OAuth2AccessTokenAuthenticationToken(registeredClient, authentication, oAuth2AccessToken, null, additionalParameters);
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

    private LEARCredential getVerifiableCredential(OAuth2AuthorizationGrantAuthenticationToken authentication) {
        Map<String, Object> additionalParameters = authentication.getAdditionalParameters();
        if (!additionalParameters.containsKey("vc")) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }
        JsonNode verifiableCredential = objectMapper.convertValue(additionalParameters.get("vc"), JsonNode.class);

        if (authentication instanceof OAuth2AuthorizationCodeAuthenticationToken) {
            return objectMapper.convertValue(verifiableCredential, LEARCredentialEmployee.class);
        } else if (authentication instanceof OAuth2ClientCredentialsAuthenticationToken) {
            return objectMapper.convertValue(verifiableCredential, LEARCredentialMachine.class);

        }

        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
    }

    private String getAudience(OAuth2AuthorizationGrantAuthenticationToken authentication, LEARCredential credential) {
        // Extraer el audience en función del tipo de credencial
        if (credential instanceof LEARCredentialMachine) {
            return securityProperties.authorizationServer();
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
                .issuer(securityProperties.authorizationServer())
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
                Long.parseLong(securityProperties.token().idToken().expiration()),
                ChronoUnit.valueOf(securityProperties.token().idToken().cronUnit())
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
                .issuer(securityProperties.authorizationServer())
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

        JWTClaimsSet idTokenClaims = idTokenClaimsBuilder.build();

        // Use JWTService to generate the ID Token (JWT)
        return jwtService.generateJWT(idTokenClaims.toString());
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
                || OAuth2ClientCredentialsAuthenticationToken.class.isAssignableFrom(authentication);
    }
}

