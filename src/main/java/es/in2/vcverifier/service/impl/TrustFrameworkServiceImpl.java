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

    private static final String ISSUER_ID_FILE_URL = "https://raw.githubusercontent.com/in2workspace/in2-verifier-api/refs/heads/feature/h2m_authn_authz_flow/mockTrustFramework/issuer_id_list.txt";
    private static final String PARTICIPANTS_ID_FILE_URL = "https://raw.githubusercontent.com/in2workspace/in2-verifier-api/refs/heads/feature/h2m_authn_authz_flow/mockTrustFramework/participants_id_list.txt";
    private static final String CLIENTS_JSON_URL = "https://raw.githubusercontent.com/in2workspace/in2-verifier-api/refs/heads/feature/h2m_authn_authz_flow/mockTrustFramework/clients.json";

    private static final HttpClient HTTP_CLIENT = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.ALWAYS) // Habilitar seguimiento de redirecciones
            .build();

    @Override
    public String fetchAllowedClient() {
        try {
            return fetchRemoteFile(CLIENTS_JSON_URL); // Reutiliza el método para obtener el JSON
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException("Error reading clients list from GitHub.", e);
        }
    }

    @Override
    public boolean isIssuerIdAllowed(String issuerId) {
        try {
            List<String> allowedIssuerIds = readRemoteFileAsList(ISSUER_ID_FILE_URL); // Reutiliza el método para obtener la lista
            return allowedIssuerIds.contains(issuerId);
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException("Error reading issuer ID list from GitHub.", e);
        }
    }

    @Override
    public boolean isParticipantIdAllowed(String participantId) {
        try {
            List<String> allowedParticipantIds = readRemoteFileAsList(PARTICIPANTS_ID_FILE_URL); // Reutiliza el método para obtener la lista
            return allowedParticipantIds.contains(participantId);
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException("Error reading participant ID list from GitHub.", e);
        }
    }

    private List<String> readRemoteFileAsList(String fileUrl) throws IOException, InterruptedException {
        String content = fetchRemoteFile(fileUrl);
        return Arrays.asList(content.split("\n")); // Convierte el contenido en lista de líneas
    }

    private String fetchRemoteFile(String fileUrl) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(fileUrl))
                .build();
        HttpResponse<String> response = HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() == 200) {
            return response.body(); // Devuelve el contenido del archivo
        } else {
            throw new IOException("Failed to fetch file from GitHub. Status code: " + response.statusCode());
        }
    }
}

