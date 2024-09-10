package es.in2.vcverifier.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final RegisteredClientRepository registeredClientRepository;

    // Método para crear el objeto Authentication a partir de un clientId
    public Authentication createAuthentication(String clientId) {
        // Recuperar el RegisteredClient a partir del clientId
        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);

        // Verificar si el cliente existe
        if (registeredClient == null) {
            throw new IllegalArgumentException("Cliente no encontrado: " + clientId);
        }

        // Crear un UserDetails que representará al cliente registrado
        UserDetails clientDetails = User.withUsername(clientId)
                .password("{noop}") // En este caso no se valida la contraseña
                .authorities(Collections.singletonList(new SimpleGrantedAuthority("ROLE_CLIENT")))
                .build();

        // Crear y devolver el objeto Authentication usando el UsernamePasswordAuthenticationToken
        return new UsernamePasswordAuthenticationToken(clientDetails, null, clientDetails.getAuthorities());
    }
}

