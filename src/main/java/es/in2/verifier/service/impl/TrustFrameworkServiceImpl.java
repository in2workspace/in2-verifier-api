package es.in2.verifier.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import es.in2.verifier.config.properties.TrustFrameworkProperties;
import es.in2.verifier.exception.FailedCommunicationException;
import es.in2.verifier.exception.IssuerNotAuthorizedException;
import es.in2.verifier.exception.JsonConversionException;
import es.in2.verifier.exception.RemoteFileFetchException;
import es.in2.verifier.model.ExternalTrustedListYamlData;
import es.in2.verifier.model.RevokedCredentialIds;
import es.in2.verifier.model.issuer.IssuerAttribute;
import es.in2.verifier.model.issuer.IssuerCredentialsCapabilities;
import es.in2.verifier.model.issuer.IssuerResponse;
import es.in2.verifier.service.TrustFrameworkService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class TrustFrameworkServiceImpl implements TrustFrameworkService {

    private final ObjectMapper objectMapper;
    private final TrustFrameworkProperties trustFrameworkProperties;
    private final ObjectMapper yamlMapper = new ObjectMapper(new YAMLFactory());

    @Override
    public ExternalTrustedListYamlData fetchAllowedClient() {
        try {
            String clientsYaml = fetchRemoteFile(trustFrameworkProperties.clientsRepository().uri());
            return yamlMapper.readValue(clientsYaml, ExternalTrustedListYamlData.class);
        } catch (IOException | InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RemoteFileFetchException("Error reading clients list from GitHub.", e);
        }
    }

    @Override
    public List<IssuerCredentialsCapabilities> getTrustedIssuerListData(String id) {
        try {
            // Step 1: Send HTTP request to fetch issuer data
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(trustFrameworkProperties.trustedIssuerList().uri() + id))
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                // Step 2: Map response to IssuerResponse object
                IssuerResponse issuerResponse = objectMapper.readValue(response.body(), IssuerResponse.class);

                // Step 3: Decode and map each attribute's body to IssuerCredentialsCapabilities
                return issuerResponse.attributes().stream()
                        .map(this::decodeAndMapIssuerAttributeBody)
                        .toList();
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

    @Override
    public List<String> getRevokedCredentialIds() {
        try {
            String revokedCredentialIdsYaml = fetchRemoteFile(trustFrameworkProperties.revocationList().uri());
            RevokedCredentialIds revokedCredentialIds = yamlMapper.readValue(revokedCredentialIdsYaml, RevokedCredentialIds.class);
            return revokedCredentialIds.revokedCredentials();
        } catch (IOException | InterruptedException e) {
            log.error("Error fetching revoked credential IDs from URI {}: {}", trustFrameworkProperties.revocationList().uri(), e.getMessage());
            Thread.currentThread().interrupt();
            throw new FailedCommunicationException("Error fetching revoked credential IDs: " + e.getMessage());
        }
    }

    // Helper method to decode Base64 and map to IssuerCredentialsCapabilities
    private IssuerCredentialsCapabilities decodeAndMapIssuerAttributeBody(IssuerAttribute issuerAttribute) {
        try {
            // Decode the Base64 body
            String decodedBody = new String(Base64.getDecoder().decode(issuerAttribute.body()), StandardCharsets.UTF_8);

            // Map the decoded string to IssuerCredentialsCapabilities
            return objectMapper.readValue(decodedBody, IssuerCredentialsCapabilities.class);
        } catch (IOException e) {
            log.error("Failed to decode and map issuer attribute body: {}", e.getMessage());
            throw new JsonConversionException("Failed to decode and map issuer attribute body");
        }
    }

    private String fetchRemoteFile(String fileUrl) throws IOException, InterruptedException {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(fileUrl))
                .build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() == 200) {
            return response.body();
        } else {
            throw new RemoteFileFetchException("Failed to fetch file from GitHub. Status code: " + response.statusCode());
        }
    }
}


