package es.in2.vcverifier.security.filters;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import es.in2.vcverifier.config.properties.SecurityProperties;
import es.in2.vcverifier.crypto.CryptoComponent;
import es.in2.vcverifier.model.LEARCredentialEmployee;
import es.in2.vcverifier.model.LEARCredentialMachine;
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
import java.util.Map;
import java.util.UUID;

@Slf4j
@RequiredArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {
    private final CryptoComponent cryptoComponent;
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
                securityProperties.token().accessToken().expiration(),
                ChronoUnit.valueOf(securityProperties.token().accessToken().cronUnit())
        );
        Object credential = getVerifiableCredential(authentication);
        String subject = getCredentialSubjectFromVerifiableCredential(credential);

        String jwtToken = generateAccessTokenWithVc(credential, issueTime, expirationTime, subject);
        OAuth2AccessToken oAuth2AccessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                jwtToken,
                issueTime,
                expirationTime
        );

        return new OAuth2AccessTokenAuthenticationToken(registeredClient, authentication, oAuth2AccessToken);
    }

    private String getClientId(OAuth2AuthorizationGrantAuthenticationToken authentication) {
        // Asumiendo que el clientId puede estar en los parámetros adicionales o como atributo
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
                .issuer(cryptoComponent.getECKey().getKeyID())
                .audience(audience) // Utiliza el valor de "audience" calculado
                .subject(subject)
                .jwtID(UUID.randomUUID().toString())
                .issueTime(Date.from(issueTime))
                .expirationTime(Date.from(expirationTime))
                .claim(OAuth2ParameterNames.CLIENT_ID, cryptoComponent.getECKey().getKeyID())
                .claim("verifiableCredential", verifiableCredential)
                .build();
        return jwtService.generateJWT(payload.toString());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2AuthorizationCodeAuthenticationToken.class.isAssignableFrom(authentication)
                || OAuth2ClientCredentialsAuthenticationToken.class.isAssignableFrom(authentication);
    }
}

