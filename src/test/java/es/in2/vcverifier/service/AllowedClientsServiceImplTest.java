package es.in2.vcverifier.service;

import es.in2.vcverifier.config.ApiConfig;
import es.in2.vcverifier.config.properties.ClientRepositoryProperties;
import es.in2.vcverifier.exception.InvalidSpringProfile;
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
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class AllowedClientsServiceImplTest {
    @Mock
    private ClientRepositoryProperties clientRepositoryProperties;

    @Mock
    private ApiConfig apiConfig;

    @Mock
    private HttpResponse<String> mockHttpResponse;

    @InjectMocks
    private AllowedClientsServiceImpl allowedClientsService;


    @Test
    void fetchAllowedClient_throws_RemoteFileFetchException() {
        String profile = "test";
        when(apiConfig.getCurrentEnvironment()).thenReturn(profile);
        when(clientRepositoryProperties.uri()).thenReturn("https://example.com/");

        RemoteFileFetchException thrown = assertThrows(RemoteFileFetchException.class, () -> allowedClientsService.fetchAllowedClient());
        assertEquals("Error reading clients list from GitHub.", thrown.getMessage());
    }

    @Test
    void fetchAllowedClient_WhenCurrentEnvironmentEmpty_ShouldThrowRemoteFileFetchException() {

        when(apiConfig.getCurrentEnvironment()).thenReturn("");
        when(clientRepositoryProperties.uri()).thenReturn("https://example.com/");

        InvalidSpringProfile thrown = assertThrows(InvalidSpringProfile.class, () -> allowedClientsService.fetchAllowedClient());
        assertEquals("Environment variable SPRING_PROFILES_ACTIVE is not set", thrown.getMessage());
    }

    @Test
    void fetchAllowedClient_WhenCurrentEnvironmentIsNull_ShouldThrowRemoteFileFetchException() {

        when(apiConfig.getCurrentEnvironment()).thenReturn(null);
        when(clientRepositoryProperties.uri()).thenReturn("https://example.com/");

        InvalidSpringProfile thrown = assertThrows(InvalidSpringProfile.class, () -> allowedClientsService.fetchAllowedClient());
        assertEquals("Environment variable SPRING_PROFILES_ACTIVE is not set", thrown.getMessage());
    }
}
