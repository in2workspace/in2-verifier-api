package es.in2.vcverifier.security.filters;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;

public class CustomAuthenticationProvider implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (authentication instanceof OAuth2AuthorizationCodeRequestAuthenticationToken) {
            // Procesa la autenticación personalizada
            // Verifica la validez del request_uri y otros parámetros necesarios
            // Retorna un objeto Authentication si es exitoso
        }
        throw new OAuth2AuthorizationCodeRequestAuthenticationException(
                new OAuth2Error(
                        "invalid_request",
                        "The request is missing a required parameter",
                        null),
                null);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2AuthorizationCodeRequestAuthenticationToken.class.isAssignableFrom(authentication);
    }

}