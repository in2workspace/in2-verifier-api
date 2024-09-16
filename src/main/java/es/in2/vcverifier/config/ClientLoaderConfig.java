package es.in2.vcverifier.config;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.vcverifier.model.ClientData;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Configuration
@RequiredArgsConstructor
public class ClientLoaderConfig {

    private final ObjectMapper objectMapper;

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        List<RegisteredClient> clients = loadClients(); // Cargar los clientes
        return new InMemoryRegisteredClientRepository(clients); // Pasar los clientes al repositorio
    }

    private List<RegisteredClient> loadClients() {
        try {
            // Leer el archivo JSON
            InputStream inputStream = getClass().getClassLoader().getResourceAsStream("clients.json");
            List<ClientData> clientsData = objectMapper.readValue(inputStream, new TypeReference<>() {
            });

            List<RegisteredClient> registeredClients = new ArrayList<>();

            // Convertir cada ClientData a RegisteredClient y agregarlo a la lista
            for (ClientData clientData : clientsData) {
                RegisteredClient.Builder registeredClientBuilder = RegisteredClient.withId(UUID.randomUUID().toString())
                        .clientId(clientData.getClientId())
                        .clientAuthenticationMethods(authMethods -> clientData.getClientAuthenticationMethods().forEach(method ->
                                authMethods.add(new ClientAuthenticationMethod(method))))
                        .authorizationGrantTypes(grantTypes -> clientData.getAuthorizationGrantTypes().forEach(grantType ->
                                grantTypes.add(new AuthorizationGrantType(grantType))))
                        .redirectUris(uris -> uris.addAll(clientData.getRedirectUris()))
                        .postLogoutRedirectUris(uris -> uris.addAll(clientData.getPostLogoutRedirectUris()))
                        .scopes(scopes -> scopes.addAll(clientData.getScopes()));

                // Configurar ClientSettings
                ClientSettings.Builder clientSettingsBuilder = ClientSettings.builder()
                        .requireAuthorizationConsent(clientData.getRequireAuthorizationConsent());

                // Configurar valores opcionales si están presentes en el JSON
                if (clientData.getJwkSetUrl() != null) {
                    clientSettingsBuilder.jwkSetUrl(clientData.getJwkSetUrl());
                }

                if (clientData.getTokenEndpointAuthenticationSigningAlgorithm() != null) {
                    clientSettingsBuilder.tokenEndpointAuthenticationSigningAlgorithm(
                            SignatureAlgorithm.from(clientData.getTokenEndpointAuthenticationSigningAlgorithm()));
                }

                if (clientData.getRequireProofKey() != null) {
                    clientSettingsBuilder.requireProofKey(clientData.getRequireProofKey());
                }

                registeredClientBuilder.clientSettings(clientSettingsBuilder.build());

                registeredClients.add(registeredClientBuilder.build());
            }
            return registeredClients;
        } catch (Exception e) {
            throw new RuntimeException("Error loading clients from JSON", e);
        }
    }

}


