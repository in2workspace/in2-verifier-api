package es.in2.vcverifier.service;

import es.in2.vcverifier.config.properties.ClientRepositoryProperties;
import es.in2.vcverifier.exception.RemoteFileFetchException;
import es.in2.vcverifier.service.impl.AllowedClientsServiceImpl;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class AllowedClientsServiceImplTest {
    @Mock
    private ClientRepositoryProperties clientRepositoryProperties;

    @InjectMocks
    private AllowedClientsServiceImpl allowedClientsService;

    @Test
    void fetchAllowedClient_throws_RemoteFileFetchException() {
        when(clientRepositoryProperties.uri()).thenReturn("https://example.com/");

        RemoteFileFetchException thrown = assertThrows(RemoteFileFetchException.class, () -> allowedClientsService.fetchAllowedClient());
        assertEquals("Error reading clients list from GitHub.", thrown.getMessage());
    }

}
