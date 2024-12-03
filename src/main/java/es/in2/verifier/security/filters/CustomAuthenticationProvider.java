package es.in2.verifier.security.filters;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import es.in2.verifier.config.properties.SecurityProperties;
import es.in2.verifier.exception.InvalidCredentialTypeException;
import es.in2.verifier.exception.JsonConversionException;
import es.in2.verifier.model.credentials.employee.LEARCredentialEmployee;
import es.in2.verifier.model.credentials.machine.LEARCredentialMachine;
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

        Object credential = getVerifiableCredential(authentication);
        String subject = getCredentialSubjectFromVerifiableCredential(credential);
        log.debug("CustomAuthenticationProvider -- handleGrant -- Credential subject obtained: {}", subject);

        String audience = getAudience(authentication,credential);
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
        return new OAuth2AccessTokenAuthenticationToken(registeredClient, authentication, oAuth2AccessToken, null,additionalParameters);
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
    private Object getVerifiableCredential(OAuth2AuthorizationGrantAuthenticationToken authentication) {
        // Obtener el JsonNode de los parámetros adicionales
        Map<String, Object> additionalParameters = authentication.getAdditionalParameters();
        if (!additionalParameters.containsKey("vc")) {
            log.error("CustomAuthenticationProvider -- getVerifiableCredential -- Parameter 'vc' not found in request");
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }
        JsonNode verifiableCredential = objectMapper.convertValue(additionalParameters.get("vc"), JsonNode.class);
        log.debug("CustomAuthenticationProvider -- getVerifiableCredential -- Verifiable credential obtained: {}", verifiableCredential);

        // Diferenciar el tipo de credencial basado en la clase concreta de autenticación
        if (authentication instanceof OAuth2AuthorizationCodeAuthenticationToken) {
            // Retorna la credencial específica para el tipo `LEARCredentialEmployee`
            return objectMapper.convertValue(verifiableCredential, LEARCredentialEmployee.class);
        } else if (authentication instanceof OAuth2ClientCredentialsAuthenticationToken) {
            // Retorna la credencial específica para el tipo `LEARCredentialMachine`
            return objectMapper.convertValue(verifiableCredential, LEARCredentialMachine.class);
        }
        log.error("CustomAuthenticationProvider -- getVerifiableCredential -- Unsupported authentication type for credential");
        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
    }

    private String getCredentialSubjectFromVerifiableCredential(Object verifiableCredential) {
        log.debug("CustomAuthenticationProvider -- getCredentialSubjectFromVerifiableCredential -- Obtaining subject from verifiable credential");
        if (verifiableCredential instanceof LEARCredentialEmployee learCredentialEmployee) {
            // Extrae y retorna el credentialSubject específico para `LEARCredentialEmployee`
            return learCredentialEmployee.credentialSubject().mandate().mandatee().id();
        } else if (verifiableCredential instanceof LEARCredentialMachine learCredentialMachine) {
            // Extrae y retorna el credentialSubject específico para `LEARCredentialMachine`
            return learCredentialMachine.credentialSubject().mandate().mandatee().id();
        }
        log.error("CustomAuthenticationProvider -- getCredentialSubjectFromVerifiableCredential -- Unsupported credential LEARCredentialType: {}", verifiableCredential.getClass().getName());
        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
    }

    private String getAudience(OAuth2AuthorizationGrantAuthenticationToken authentication, Object credential) {
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

    private String generateAccessTokenWithVc(Object verifiableCredential, Instant issueTime, Instant expirationTime, String subject, String audience) {
        log.info("Generating access token with verifiableCredential");

        // Convert the VerifiableCredential to a JSON node
        JsonNode vcJsonNode = convertCredentialToJsonNode(verifiableCredential);
        Map<String, Object> vcMap = jsonNodeToMap(vcJsonNode);

        JWTClaimsSet payload = new JWTClaimsSet.Builder()
                .issuer(securityProperties.authorizationServer())
                .audience(audience)
                .subject(subject)
                .jwtID(UUID.randomUUID().toString())
                .issueTime(Date.from(issueTime))
                .expirationTime(Date.from(expirationTime))
                .claim(OAuth2ParameterNames.SCOPE, getScope(verifiableCredential))
                .claim("vc", vcMap)
                .build();
        return jwtService.generateJWT(payload.toString());
    }

    private String generateIdToken(Object verifiableCredential, String subject, String audience, Map<String, Object> additionalParameters) {
        Instant issueTime = Instant.now();
        Instant expirationTime = issueTime.plus(
                Long.parseLong(securityProperties.token().idToken().expiration()),
                ChronoUnit.valueOf(securityProperties.token().idToken().cronUnit())
        );

        // Convert the VerifiableCredential to a JSON string
        String verifiableCredentialJson;
        try {
            verifiableCredentialJson = objectMapper.writeValueAsString(verifiableCredential);
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
            additionalClaims = extractClaimsFromVerifiableCredential(verifiableCredential, additionalParameters);
            additionalClaims.forEach(idTokenClaimsBuilder::claim);
        }

        JWTClaimsSet idTokenClaims = idTokenClaimsBuilder.build();

        // Use JWTService to generate the ID Token (JWT)
        return jwtService.generateJWT(idTokenClaims.toString());
    }

    private JsonNode convertCredentialToJsonNode(Object verifiableCredential) {
        try {
            if (verifiableCredential instanceof LEARCredentialEmployee learCredentialEmployee) {
                return objectMapper.valueToTree(learCredentialEmployee);
            } else if (verifiableCredential instanceof LEARCredentialMachine learCredentialMachine) {
                return objectMapper.valueToTree(learCredentialMachine);
            } else {
                log.error("Unsupported verifiable credential type: {}", verifiableCredential.getClass().getName());
                throw new InvalidCredentialTypeException("Unsupported verifiable credential type: " + verifiableCredential.getClass().getName());
            }
        } catch (Exception e) {
            log.error("Error converting verifiable credential to JsonNode", e);
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }
    }

    private Map<String, Object> jsonNodeToMap(JsonNode jsonNode) {
        return objectMapper.convertValue(jsonNode, new TypeReference<>() {
        });
    }


    private Map<String, Object> extractClaimsFromVerifiableCredential(Object verifiableCredential, Map<String, Object> additionalParameters) {
        Set<String> requestedScopes = new HashSet<>(Arrays.asList(additionalParameters.get(OAuth2ParameterNames.SCOPE).toString().split(" ")));
        Map<String, Object> claims = new HashMap<>();

        if (verifiableCredential instanceof LEARCredentialEmployee learCredentialEmployee) {
            // Check if "profile" scope is requested and add profile-related claims
            if (requestedScopes.contains("profile")) {
                String firstName = learCredentialEmployee.credentialSubject().mandate().mandatee().firstName();
                String lastName = learCredentialEmployee.credentialSubject().mandate().mandatee().lastName();
                String name = firstName + " " + lastName;
                claims.put("name", name);
                claims.put("given_name", firstName);
                claims.put("family_name", lastName);
            }

            // Check if "email" scope is requested and add email-related claims
            if (requestedScopes.contains("email")) {
                claims.put("email", learCredentialEmployee.credentialSubject().mandate().mandatee().email());
                claims.put("email_verified", true);
            }
        }
        return claims;
    }


    private String getScope(Object verifiableCredential){
        if (verifiableCredential instanceof LEARCredentialEmployee) {
            return "openid learcredential";
        } else if (verifiableCredential instanceof LEARCredentialMachine) {
            return "machine learcredential";
        } else {
            log.error("CustomAuthenticationProvider -- getScope -- Unsupported credential type: {}", verifiableCredential.getClass().getName());
            throw new InvalidCredentialTypeException("Credential Type not supported: " + verifiableCredential.getClass().getName());
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2AuthorizationCodeAuthenticationToken.class.isAssignableFrom(authentication)
                || OAuth2ClientCredentialsAuthenticationToken.class.isAssignableFrom(authentication);
    }
}

