package es.in2.verifier.infrastructure.config;

import es.in2.verifier.domain.exception.ClientLoadingException;
import es.in2.verifier.domain.model.dto.ClientData;
import es.in2.verifier.domain.model.dto.ExternalTrustedListYamlData;
import es.in2.verifier.domain.service.TrustFrameworkService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DomeTrustFrameworkConfigTest {

    @Mock
    private TrustFrameworkService trustFrameworkService;

    @InjectMocks
    private DomeTrustFrameworkConfig domeTrustFrameworkConfig;

    @Test
    void loadClientsReturnsEmptyListWhenNoClients() {
        when(trustFrameworkService.fetchAllowedClient()).thenReturn(new ExternalTrustedListYamlData(new ArrayList<>()));

        List<RegisteredClient> clients = domeTrustFrameworkConfig.loadClients();

        assertNotNull(clients);
        assertTrue(clients.isEmpty());
    }

    @Test
    void loadClientsThrowsClientLoadingExceptionOnError() {
        when(trustFrameworkService.fetchAllowedClient()).thenThrow(new RuntimeException("Error"));

        assertThrows(ClientLoadingException.class, () -> domeTrustFrameworkConfig.loadClients());
    }

}
