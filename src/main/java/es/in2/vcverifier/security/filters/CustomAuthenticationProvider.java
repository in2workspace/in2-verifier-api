package es.in2.vcverifier.security.filters;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import es.in2.vcverifier.config.CacheStore;
import es.in2.vcverifier.config.properties.SecurityProperties;
import es.in2.vcverifier.crypto.CryptoComponent;
import es.in2.vcverifier.model.AuthorizationCodeData;
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
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.UUID;

@Slf4j
@RequiredArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {
    private final CacheStore<AuthorizationCodeData> cacheStoreForAuthorizationCodeData;
    private final CryptoComponent cryptoComponent;
    private final JWTService jwtService;
    private final RegisteredClientRepository registeredClientRepository; // Repositorio para obtener el RegisteredClient
    private final SecurityProperties securityProperties;
    private final ObjectMapper objectMapper;



    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (authentication instanceof OAuth2AuthorizationCodeAuthenticationToken) {
            return handleH2MGrant((OAuth2AuthorizationCodeAuthenticationToken) authentication);
        } else if (authentication instanceof OAuth2ClientCredentialsAuthenticationToken) {
            return handleM2MGrant((OAuth2ClientCredentialsAuthenticationToken) authentication);
        }
        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNSUPPORTED_GRANT_TYPE);
    }

    private Authentication handleH2MGrant(OAuth2AuthorizationCodeAuthenticationToken authentication) {
        // Recupera datos de la caché
        String code = authentication.getCode();
        AuthorizationCodeData authorizationCodeData = cacheStoreForAuthorizationCodeData.get(code);

        if (authorizationCodeData == null) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }

        RegisteredClient registeredClient = registeredClientRepository.findByClientId(authorizationCodeData.clientId());

        if (registeredClient == null) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }

        Instant issueTime = Instant.now();
        Instant expirationTime = issueTime.plus(securityProperties.token().accessToken().expiration(), ChronoUnit.valueOf(securityProperties.token().accessToken().cronUnit()));
        String jwtToken = generateAccessTokenWithVc(authorizationCodeData.verifiableCredential(),issueTime,expirationTime);
        OAuth2AccessToken oAuth2AccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,jwtToken,issueTime,expirationTime);

        return new OAuth2AccessTokenAuthenticationToken(registeredClient, authentication, oAuth2AccessToken);
    }

    private Authentication handleM2MGrant(OAuth2ClientCredentialsAuthenticationToken authentication) {
        String clientId = authentication.getAdditionalParameters().get("clientId").toString();
        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);

        if (registeredClient == null) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }

        Instant issueTime = Instant.now();
        Instant expirationTime = issueTime.plus(securityProperties.token().accessToken().expiration(), ChronoUnit.valueOf(securityProperties.token().accessToken().cronUnit()));

        JsonNode jsonNode = (JsonNode) authentication.getAdditionalParameters().get("vc");

        LEARCredentialMachine learCredentialMachine = objectMapper.convertValue(jsonNode, LEARCredentialMachine.class);

        String jwtToken = generateAccessTokenWithVc(learCredentialMachine,issueTime,expirationTime);
        OAuth2AccessToken oAuth2AccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,jwtToken,issueTime,expirationTime);
        return new OAuth2AccessTokenAuthenticationToken(registeredClient, authentication, oAuth2AccessToken);
    }

    private String generateAccessTokenWithVc(Object verifiableCredential,Instant issueTime,Instant expirationTime){
        JWTClaimsSet payload = new JWTClaimsSet.Builder()
                .issuer(cryptoComponent.getECKey().getKeyID())
                .audience(cryptoComponent.getECKey().getKeyID())
                .jwtID(UUID.randomUUID().toString())
                .issueTime(Date.from(issueTime))
                .expirationTime(Date.from(expirationTime))
                .claim("client_id", cryptoComponent.getECKey().getKeyID())
                .claim("verifiableCredential", verifiableCredential)
                //.claim("scope", )
                .build();
        return jwtService.generateJWT(payload.toString());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2AuthorizationCodeAuthenticationToken.class.isAssignableFrom(authentication)
                || OAuth2ClientCredentialsAuthenticationToken.class.isAssignableFrom(authentication);
    }
}

