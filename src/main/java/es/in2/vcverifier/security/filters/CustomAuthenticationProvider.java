package es.in2.vcverifier.security.filters;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import es.in2.vcverifier.config.properties.SecurityProperties;
import es.in2.vcverifier.exception.InvalidCredentialTypeException;
import es.in2.vcverifier.model.credentials.employee.LEARCredentialEmployee;
import es.in2.vcverifier.model.credentials.machine.LEARCredentialMachine;
import es.in2.vcverifier.service.JWTService;
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
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static es.in2.vcverifier.util.Constants.NONCE;

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
            return handleGrant(oAuth2AuthorizationGrantAuthenticationToken);
        }
        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNSUPPORTED_GRANT_TYPE);
    }

    private Authentication handleGrant(OAuth2AuthorizationGrantAuthenticationToken authentication) {
        String clientId = getClientId(authentication);
        RegisteredClient registeredClient = getRegisteredClient(clientId);

        Instant issueTime = Instant.now();
        Instant expirationTime = issueTime.plus(
                Long.parseLong(securityProperties.token().accessToken().expiration()),
                ChronoUnit.valueOf(securityProperties.token().accessToken().cronUnit())
        );
        Object credential = getVerifiableCredential(authentication);
        String subject = getCredentialSubjectFromVerifiableCredential(credential);
        String audience = getAudience(authentication,credential);
        String nonce = getNonce(authentication);

        String jwtToken = generateAccessTokenWithVc(credential, issueTime, expirationTime, subject, audience);
        OAuth2AccessToken oAuth2AccessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                jwtToken,
                issueTime,
                expirationTime
        );

        String idToken = generateIdToken(credential, subject, audience, nonce);

        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put("id_token", idToken);

        return new OAuth2AccessTokenAuthenticationToken(registeredClient, authentication, oAuth2AccessToken, null,additionalParameters);
    }

    private String getNonce(OAuth2AuthorizationGrantAuthenticationToken authentication) {
        Map<String, Object> additionalParameters = authentication.getAdditionalParameters();
        if (additionalParameters != null && additionalParameters.containsKey(NONCE)) {
            return additionalParameters.get(NONCE).toString();
        }

        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
    }

    private String getClientId(OAuth2AuthorizationGrantAuthenticationToken authentication) {
        Map<String, Object> additionalParameters = authentication.getAdditionalParameters();
        if (additionalParameters != null && additionalParameters.containsKey(OAuth2ParameterNames.CLIENT_ID)) {
            return additionalParameters.get(OAuth2ParameterNames.CLIENT_ID).toString();
        }

        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
    }


    private RegisteredClient getRegisteredClient(String clientId) {
        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }
        return registeredClient;
    }
    private Object getVerifiableCredential(OAuth2AuthorizationGrantAuthenticationToken authentication) {
        // Obtener el JsonNode de los parámetros adicionales
        Map<String, Object> additionalParameters = authentication.getAdditionalParameters();
        if (!additionalParameters.containsKey("vc")) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }
        JsonNode verifiableCredential = objectMapper.convertValue(additionalParameters.get("vc"), JsonNode.class);

        // Diferenciar el tipo de credencial basado en la clase concreta de autenticación
        if (authentication instanceof OAuth2AuthorizationCodeAuthenticationToken) {
            // Retorna la credencial específica para el tipo `LEARCredentialEmployee`
            return objectMapper.convertValue(verifiableCredential, LEARCredentialEmployee.class);
        } else if (authentication instanceof OAuth2ClientCredentialsAuthenticationToken) {
            // Retorna la credencial específica para el tipo `LEARCredentialMachine`
            return objectMapper.convertValue(verifiableCredential, LEARCredentialMachine.class);
        }

        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
    }

    private String getCredentialSubjectFromVerifiableCredential(Object verifiableCredential) {
        if (verifiableCredential instanceof LEARCredentialEmployee learCredentialEmployee) {
            // Extrae y retorna el credentialSubject específico para `LEARCredentialEmployee`
            return learCredentialEmployee.credentialSubject().mandate().mandatee().id();
        } else if (verifiableCredential instanceof LEARCredentialMachine learCredentialMachine) {
            // Extrae y retorna el credentialSubject específico para `LEARCredentialMachine`
            return learCredentialMachine.credentialSubject().mandate().mandatee().id();
        }

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
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
            }
        }

        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
    }

    private String generateAccessTokenWithVc(Object verifiableCredential, Instant issueTime, Instant expirationTime, String subject, String audience) {
        JWTClaimsSet payload = new JWTClaimsSet.Builder()
                .issuer(securityProperties.authorizationServer())
                .audience(audience)
                .subject(subject)
                .issueTime(Date.from(issueTime))
                .expirationTime(Date.from(expirationTime))
                .claim(OAuth2ParameterNames.SCOPE, getScope(verifiableCredential))
                .claim("vc", verifiableCredential)
                .build();
        return jwtService.generateJWT(payload.toString());
    }

    private String generateIdToken(Object verifiableCredential, String subject, String audience, String nonce) {
        // Extract additional claims from the verifiable credential
        Map<String, Object> additionalClaims = extractClaimsFromVerifiableCredential(verifiableCredential);

        Instant issueTime = Instant.now();
        Instant expirationTime = issueTime.plus(
                Long.parseLong(securityProperties.token().idToken().expiration()),
                ChronoUnit.valueOf(securityProperties.token().idToken().cronUnit())
        );

        // Fixme - This is a workaround to convert the verifiableCredential to a JSON string
        // Convert verifiableCredential to JSON string
        String vcJsonString;
        try {
            vcJsonString = new ObjectMapper().writeValueAsString(verifiableCredential);
        } catch (Exception e) {
            throw new RuntimeException("Failed to convert verifiableCredential to JSON string", e);
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
                .claim(NONCE, nonce)
                .claim("vc", vcJsonString); // Use the JSON string here

        // Add each additional claim to the ID token
        additionalClaims.forEach(idTokenClaimsBuilder::claim);

        JWTClaimsSet idTokenClaims = idTokenClaimsBuilder.build();

        // Use JWTService to generate the ID Token (JWT)
        return jwtService.generateJWT(idTokenClaims.toString());
    }


    private Map<String, Object> extractClaimsFromVerifiableCredential(Object verifiableCredential) {
        Map<String, Object> claims = new HashMap<>();

        if (verifiableCredential instanceof LEARCredentialEmployee learCredentialEmployee) {
            String name = learCredentialEmployee.credentialSubject().mandate().mandatee().firstName() + " " + learCredentialEmployee.credentialSubject().mandate().mandatee().lastName();
            String givenName = learCredentialEmployee.credentialSubject().mandate().mandatee().firstName();
            String familyName = learCredentialEmployee.credentialSubject().mandate().mandatee().lastName();
            String email = learCredentialEmployee.credentialSubject().mandate().mandatee().email();

            claims.put("name", name);
            claims.put("given_name", givenName);
            claims.put("family_name", familyName);
            claims.put("email", email);
            claims.put("email_verified", true);
        }

        return claims;
    }


    private String getScope(Object verifiableCredential){
        if (verifiableCredential instanceof LEARCredentialEmployee) {
            return "openid learcredential";
        } else if (verifiableCredential instanceof LEARCredentialMachine) {
            return "machine learcredential";
        } else {
            throw new InvalidCredentialTypeException("Credential Type not supported: " + verifiableCredential.getClass().getName());
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2AuthorizationCodeAuthenticationToken.class.isAssignableFrom(authentication)
                || OAuth2ClientCredentialsAuthenticationToken.class.isAssignableFrom(authentication);
    }
}

