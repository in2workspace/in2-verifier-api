package es.in2.vcverifier.service.impl;

import es.in2.vcverifier.exception.FailedCommunicationException;
import es.in2.vcverifier.service.HttpClientService;
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
public class HttpClientServiceImpl implements HttpClientService {

    private final HttpClient httpClient;

    @Override
    public HttpResponse<String> performGetRequest(String url) {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .GET()
                    .build();

            return httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        } catch (IOException | InterruptedException e) {
            log.error("Error during HTTP GET request to {}: {}", url, e.getMessage());
            Thread.currentThread().interrupt(); // Restore interrupted state
            throw new FailedCommunicationException("Error during HTTP GET request to " + url);
        }
    }
}

