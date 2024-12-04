package es.in2.verifier.config;

import es.in2.verifier.exception.ClientLoadingException;
import es.in2.verifier.model.ClientData;
import es.in2.verifier.model.ExternalTrustedListYamlData;
import es.in2.verifier.service.TrustFrameworkService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;

@Configuration
@RequiredArgsConstructor
public class ClientLoaderConfig {

    private final TrustFrameworkService trustFrameworkService;
    private final Set<String> allowedClientsOrigins;

    @Bean
    public RegisteredClientRepository getRegisteredClientRepository() {
        return registeredClientRepository();
    }

    @Scheduled(cron = "0 */30 * * * *")
    private RegisteredClientRepository registeredClientRepository() {
        List<RegisteredClient> clients = loadClients(); // Cargar los clientes
        return new InMemoryRegisteredClientRepository(clients); // Pasar los clientes al repositorio
    }

    private List<RegisteredClient> loadClients() {
        try {
            // Leer el archivo YAML
            ExternalTrustedListYamlData clientsYamlData = trustFrameworkService.fetchAllowedClient();
            List<RegisteredClient> registeredClients = new ArrayList<>();
            // Convertir cada ClientData a RegisteredClient y agregarlo a la lista
            for (ClientData clientData : clientsYamlData.clients()) {
                RegisteredClient.Builder registeredClientBuilder = RegisteredClient
                        .withId(UUID.randomUUID().toString())
                        .clientId(clientData.clientId())
                        .clientAuthenticationMethods(authMethods -> clientData.clientAuthenticationMethods().forEach(method -> authMethods.add(new ClientAuthenticationMethod(method))))
                        .authorizationGrantTypes(grantTypes -> clientData.authorizationGrantTypes().forEach(grantType -> grantTypes.add(new AuthorizationGrantType(grantType))))
                        .redirectUris(uris -> uris.addAll(clientData.redirectUris()))
                        .postLogoutRedirectUris(uris -> uris.addAll(clientData.postLogoutRedirectUris()))
                        .scopes(scopes -> scopes.addAll(clientData.scopes()))
                        .clientName(clientData.url());

                if (clientData.clientSecret() != null && !clientData.clientSecret().isBlank()) {
                    registeredClientBuilder.clientSecret(clientData.clientSecret());
                }
                // Configurar ClientSettings
                ClientSettings.Builder clientSettingsBuilder = ClientSettings.builder().requireAuthorizationConsent(clientData.requireAuthorizationConsent());
                // Configurar valores opcionales si están presentes en el JSON
                if (clientData.jwkSetUrl() != null) {
                    clientSettingsBuilder.jwkSetUrl(clientData.jwkSetUrl());
                }
                if (clientData.tokenEndpointAuthenticationSigningAlgorithm() != null) {
                    clientSettingsBuilder.tokenEndpointAuthenticationSigningAlgorithm(SignatureAlgorithm.from(clientData.tokenEndpointAuthenticationSigningAlgorithm()));
                }
                if (clientData.requireProofKey() != null) {
                    clientSettingsBuilder.requireProofKey(clientData.requireProofKey());
                }
                registeredClientBuilder.clientSettings(clientSettingsBuilder.build());
                registeredClients.add(registeredClientBuilder.build());

                // Add the client origin to the allowed clients origins
                if (clientData.url() != null && !clientData.url().isBlank()) {
                    allowedClientsOrigins.add(clientData.url());
                }
            }
            return registeredClients;
        } catch (Exception e) {
            throw new ClientLoadingException("Error loading clients from Yaml", e);
        }
    }
}