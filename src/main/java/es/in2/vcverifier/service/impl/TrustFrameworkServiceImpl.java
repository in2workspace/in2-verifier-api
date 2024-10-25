package es.in2.vcverifier.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.vcverifier.config.properties.TrustedIssuerListProperties;
import es.in2.vcverifier.exception.FailedCommunicationException;
import es.in2.vcverifier.exception.IssuerNotAuthorizedException;
import es.in2.vcverifier.exception.JsonConversionException;
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

    private final TrustedIssuerListProperties trustedIssuerListProperties;
    private final ObjectMapper objectMapper;
    private final HttpClientService httpClientService;

    @Override
    public List<IssuerCredentialsCapabilities> getTrustedIssuerListData(String id) {
        HttpResponse<String> response = httpClientService.performGetRequest(trustedIssuerListProperties.uri() + id);

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
}


