package es.in2.vcverifier.service;

import es.in2.vcverifier.config.properties.ClientRepositoryProperties;
import es.in2.vcverifier.exception.RemoteFileFetchException;
import es.in2.vcverifier.service.impl.AllowedClientsServiceImpl;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.net.http.HttpResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AllowedClientsServiceImplTest {

    @Mock
    private ClientRepositoryProperties clientRepositoryProperties;

    @Mock
    private HttpClientService httpClientService;

    @InjectMocks
    private AllowedClientsServiceImpl allowedClientsService;

    @Test
    void fetchAllowedClient_ReturnsFileContent() {
        // Setup
        String fileUrl = "https://example.com/";
        String expectedContent = "client list content";

        when(clientRepositoryProperties.uri()).thenReturn(fileUrl);

        // Mocking HttpResponse and HttpClientService
        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockResponse.body()).thenReturn(expectedContent);
        when(httpClientService.performGetRequest(fileUrl)).thenReturn(mockResponse);

        // Action
        String actualContent = allowedClientsService.fetchAllowedClient();

        // Assert
        assertEquals(expectedContent, actualContent, "The returned content should match the expected file content.");
    }

    @Test
    void fetchAllowedClient_throws_RemoteFileFetchException() {
        // Setup
        String fileUrl = "https://example.com/";
        when(clientRepositoryProperties.uri()).thenReturn(fileUrl);

        // Simulate an exception during HTTP request
        when(httpClientService.performGetRequest(fileUrl)).thenThrow(new RemoteFileFetchException("Error reading clients list from GitHub."));

        // Assert
        RemoteFileFetchException thrown = assertThrows(RemoteFileFetchException.class, () -> allowedClientsService.fetchAllowedClient());
        assertEquals("Error reading clients list from GitHub.", thrown.getMessage());
    }
}
