package es.in2.vcverifier.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import es.in2.vcverifier.config.properties.TrustFrameworkProperties;
import es.in2.vcverifier.exception.FailedCommunicationException;
import es.in2.vcverifier.exception.IssuerNotAuthorizedException;
import es.in2.vcverifier.exception.JsonConversionException;
import es.in2.vcverifier.exception.RemoteFileFetchException;
import es.in2.vcverifier.model.ExternalTrustedListYamlData;
import es.in2.vcverifier.model.RevokedCredentialIds;
import es.in2.vcverifier.model.issuer.IssuerAttribute;
import es.in2.vcverifier.model.issuer.IssuerCredentialsCapabilities;
import es.in2.vcverifier.model.issuer.IssuerResponse;
import es.in2.vcverifier.service.HttpClientService;
import es.in2.vcverifier.service.TrustFrameworkService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.IOException;
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
    private final HttpClientService httpClientService;
    private final ObjectMapper yamlMapper = new ObjectMapper(new YAMLFactory());

    @Override
    public ExternalTrustedListYamlData fetchAllowedClient() {
        try {
            String clientsYaml = fetchRemoteFile(trustFrameworkProperties.clientsRepository().uri());
            return yamlMapper.readValue(clientsYaml, ExternalTrustedListYamlData.class);
        } catch (JsonProcessingException e) {
            throw new JsonConversionException("Error reading clients list from GitHub: " + e);
        }
    }

    @Override
    public List<IssuerCredentialsCapabilities> getTrustedIssuerListData(String id) {
        String uri = trustFrameworkProperties.trustedIssuerList().uri() + id;
        HttpResponse<String> response = httpClientService.performGetRequest(uri);

        // Handle the response directly here
        if (response.statusCode() == 200) {
            // Step 2: Map response to IssuerResponse object
            IssuerResponse issuerResponse;
            try {
                issuerResponse = objectMapper.readValue(response.body(), IssuerResponse.class);
            } catch (IOException e) {
                log.error("Error mapping response to IssuerResponse: {}", e.getMessage());
                throw new JsonConversionException("Error mapping response to IssuerResponse");
            }

            // Step 3: Decode and map each attribute's body to IssuerCredentialsCapabilities
            return issuerResponse.attributes().stream()
                    .map(this::decodeAndMapIssuerAttributeBody)
                    .toList();
        } else if (response.statusCode() == 404) {
            throw new IssuerNotAuthorizedException("Issuer with id: " + id + " not found.");
        } else {
            throw new FailedCommunicationException("Failed to fetch issuer data. Status code: " + response.statusCode());
        }
    }

    @Override
    public List<String> getRevokedCredentialIds() {
        try {
            String revokedCredentialIdsYaml = fetchRemoteFile(trustFrameworkProperties.revocationList().uri());
            RevokedCredentialIds revokedCredentialIds = yamlMapper.readValue(revokedCredentialIdsYaml, RevokedCredentialIds.class);
            return revokedCredentialIds.revokedCredentials();
        } catch (JsonProcessingException e) {
            log.error("Error reading revoked credential IDs from URI {}: {}", trustFrameworkProperties.revocationList().uri(), e.getMessage());
            throw new JsonConversionException("Error reading revoked credential IDs: " + e.getMessage());
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

    private String fetchRemoteFile(String fileUrl){
        HttpResponse<String> response = httpClientService.performGetRequest(fileUrl);
        if (response.statusCode() == 200) {
            return response.body();
        } else {
            throw new RemoteFileFetchException("Failed to fetch file from GitHub. Status code: " + response.statusCode());
        }
    }
}


