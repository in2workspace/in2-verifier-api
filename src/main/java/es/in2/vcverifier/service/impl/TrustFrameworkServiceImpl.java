package es.in2.vcverifier.service.impl;

import es.in2.vcverifier.service.TrustFrameworkService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Arrays;
import java.util.List;

@Service
@Slf4j
public class TrustFrameworkServiceImpl implements TrustFrameworkService {

    private static final String ISSUER_ID_FILE_URL = "https://github.com/in2workspace/in2-verifier-api/tree/feature/h2m_authn_authz_flow/mockTrustFramework/issuer_id_list.txt";
    private static final String PARTICIPANTS_ID_FILE_URL = "https://github.com/in2workspace/in2-verifier-api/tree/feature/h2m_authn_authz_flow/mockTrustFramework/participants_id_list.txt";

    private static final String CLIENTS_JSON_URL = "https://github.com/in2workspace/in2-verifier-api/tree/feature/h2m_authn_authz_flow/mockTrustFramework/clients.json";

    @Override
    public String fetchAllowedClient() {
        try {
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(CLIENTS_JSON_URL))
                    .build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                return response.body();
            } else {
                throw new IOException("Failed to fetch file from GitHub. Status code: " + response.statusCode());
            }
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException("Error reading clients list.", e);
        }
    }
    @Override
    public boolean isIssuerIdAllowed(String issuerId) {
        try {
            List<String> allowedIssuerIds = readRemoteFile(ISSUER_ID_FILE_URL);
            return allowedIssuerIds.contains(issuerId);
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException("Error reading issuer ID list from GitHub.", e);
        }
    }

    @Override
    public boolean isParticipantIdAllowed(String participantId) {
        try {
            List<String> allowedParticipantIds = readRemoteFile(PARTICIPANTS_ID_FILE_URL);
            return allowedParticipantIds.contains(participantId);
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException("Error reading participant ID list.", e);
        }
    }
    private List<String> readRemoteFile(String fileUrl) throws IOException, InterruptedException {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(fileUrl))
                .build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() == 200) {
            // Dividir el contenido en líneas y devolver como lista
            return Arrays.asList(response.body().split("\n"));
        } else {
            throw new IOException("Failed to fetch file from GitHub. Status code: " + response.statusCode());
        }
    }

}
