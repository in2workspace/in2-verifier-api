package es.in2.vcverifier.security.filters;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import es.in2.vcverifier.config.properties.SecurityProperties;
import es.in2.vcverifier.exception.InvalidCredentialTypeException;
import es.in2.vcverifier.exception.JsonConversionException;
import es.in2.vcverifier.model.credentials.VerifiableCredential;
import es.in2.vcverifier.model.credentials.lear.employee.LEARCredentialEmployee;
import es.in2.vcverifier.model.credentials.lear.machine.LEARCredentialMachine;
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
        VerifiableCredential credential = getVerifiableCredential(authentication);
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
    private VerifiableCredential getVerifiableCredential(OAuth2AuthorizationGrantAuthenticationToken authentication) {
        // Obtain the JsonNode from the additional parameters
        Map<String, Object> additionalParameters = authentication.getAdditionalParameters();
        if (!additionalParameters.containsKey("vc")) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }
        JsonNode verifiableCredential = objectMapper.convertValue(additionalParameters.get("vc"), JsonNode.class);

        // TODO This determination should be done in a more robust way for example by the type of the credential
        // Determine the specific credential type based on the authentication class
        if (authentication instanceof OAuth2AuthorizationCodeAuthenticationToken) {
            return objectMapper.convertValue(verifiableCredential, LEARCredentialEmployee.class);
        } else if (authentication instanceof OAuth2ClientCredentialsAuthenticationToken) {
            return objectMapper.convertValue(verifiableCredential, LEARCredentialMachine.class);
        }

        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
    }

    private String getCredentialSubjectFromVerifiableCredential(VerifiableCredential verifiableCredential) {
        if (verifiableCredential instanceof LEARCredentialEmployee employeeCredential) {
            // Get the specific CredentialSubject
            LEARCredentialEmployee.CredentialSubject credentialSubject = employeeCredential.getLearCredentialSubject();
            return credentialSubject.mandate().mandatee().id();
        } else if (verifiableCredential instanceof LEARCredentialMachine machineCredential) {
            // Get the specific CredentialSubject
            LEARCredentialMachine.CredentialSubject credentialSubject = machineCredential.getLearMachineSubject();
            return credentialSubject.mandate().mandatee().id();
        }

        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
    }

    private String getAudience(OAuth2AuthorizationGrantAuthenticationToken authentication, VerifiableCredential credential) {
        if (credential instanceof LEARCredentialMachine) {
            return securityProperties.authorizationServer();
        } else if (credential instanceof LEARCredentialEmployee) {
            Map<String, Object> additionalParameters = authentication.getAdditionalParameters();
            if (additionalParameters.containsKey(OAuth2ParameterNames.AUDIENCE)) {
                return additionalParameters.get(OAuth2ParameterNames.AUDIENCE).toString();
            } else {
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
            }
        }

        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
    }

    private String generateAccessTokenWithVc(VerifiableCredential verifiableCredential, Instant issueTime, Instant expirationTime, String subject, String audience) {
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

    private String generateIdToken(VerifiableCredential verifiableCredential, String subject, String audience, String nonce) {
        // Extract additional claims from the verifiable credential
        Map<String, Object> additionalClaims = extractClaimsFromVerifiableCredential(verifiableCredential);

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
                .claim(NONCE, nonce)
                // Here is used in json format string to be able to save the VC in json format as Keycloak user attribute
                .claim("vc", verifiableCredentialJson);

        // Add each additional claim to the ID token
        additionalClaims.forEach(idTokenClaimsBuilder::claim);

        JWTClaimsSet idTokenClaims = idTokenClaimsBuilder.build();

        // Use JWTService to generate the ID Token (JWT)
        return jwtService.generateJWT(idTokenClaims.toString());
    }


    private Map<String, Object> extractClaimsFromVerifiableCredential(VerifiableCredential verifiableCredential) {
        Map<String, Object> claims = new HashMap<>();

        if (verifiableCredential instanceof LEARCredentialEmployee employeeCredential) {
            // Get the specific CredentialSubject
            LEARCredentialEmployee.CredentialSubject credentialSubject = employeeCredential.getLearCredentialSubject();

            // Extract mandatee details
            LEARCredentialEmployee.Mandatee mandatee = credentialSubject.mandate().mandatee();
            String name = mandatee.firstName() + " " + mandatee.lastName();
            String givenName = mandatee.firstName();
            String familyName = mandatee.lastName();
            String email = mandatee.email();

            // Populate claims
            claims.put("name", name);
            claims.put("given_name", givenName);
            claims.put("family_name", familyName);
            claims.put("email", email);
            claims.put("email_verified", true);
        }

        return claims;
    }


    private String getScope(VerifiableCredential verifiableCredential) {
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

