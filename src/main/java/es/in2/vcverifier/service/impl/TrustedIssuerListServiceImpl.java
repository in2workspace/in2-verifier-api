package es.in2.vcverifier.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.vcverifier.config.properties.TrustedIssuerListProperties;
import es.in2.vcverifier.exception.FailedCommunicationException;
import es.in2.vcverifier.exception.IssuerNotAuthorizedException;
import es.in2.vcverifier.model.issuer.IssuerCredentialsCapabilities;
import es.in2.vcverifier.service.TrustedIssuerListService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

@Service
@RequiredArgsConstructor
@Slf4j
public class TrustedIssuerListServiceImpl implements TrustedIssuerListService {

    private final TrustedIssuerListProperties trustedIssuerListProperties;
    private final ObjectMapper objectMapper;

    @Override
    public IssuerCredentialsCapabilities getTrustedIssuerListData(String id) {
        try {
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(trustedIssuerListProperties.uri() + id))
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                return objectMapper.readValue(response.body(), IssuerCredentialsCapabilities.class);
            } else if (response.statusCode() == 404) {
                throw new IssuerNotAuthorizedException("Issuer with id: " + id + " not found.");
            } else {
                throw new IOException("Failed to fetch issuer data. Status code: " + response.statusCode());
            }
        } catch (IssuerNotAuthorizedException e) {
            log.error("Issuer not found: {}", e.getMessage());
            throw e;
        } catch (IOException | InterruptedException e) {
            log.error("Error fetching issuer data for id {}: {}", id, e.getMessage());
            Thread.currentThread().interrupt();
            throw new FailedCommunicationException("Error fetching issuer data");
        }
    }
}


