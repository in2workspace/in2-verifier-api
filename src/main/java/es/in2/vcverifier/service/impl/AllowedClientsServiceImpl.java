package es.in2.vcverifier.service.impl;

import es.in2.vcverifier.config.ApiConfig;
import es.in2.vcverifier.config.properties.ClientRepositoryProperties;
import es.in2.vcverifier.exception.InvalidSpringProfile;
import es.in2.vcverifier.exception.RemoteFileFetchException;
import es.in2.vcverifier.model.enums.Profile;
import es.in2.vcverifier.service.AllowedClientsService;
import es.in2.vcverifier.util.Constants;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

@Service
@Slf4j
@RequiredArgsConstructor
public class AllowedClientsServiceImpl implements AllowedClientsService {
    private final ClientRepositoryProperties clientRepositoryProperties;

    private static final HttpClient HTTP_CLIENT = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.ALWAYS) // Habilitar seguimiento de redirecciones
            .build();

    @Override
    public String fetchAllowedClient() {
        try {
            return fetchRemoteFile(clientRepositoryProperties.uri());
        } catch (IOException | InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RemoteFileFetchException("Error reading clients list from GitHub.", e);
        }
    }

    private String fetchRemoteFile(String fileUrl) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(fileUrl))
                .build();
        HttpResponse<String> response = HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() == 200) {
            return response.body(); // Devuelve el contenido del archivo
        } else {
            throw new RemoteFileFetchException("Failed to fetch file from GitHub. Status code: " + response.statusCode());
        }
    }
}
