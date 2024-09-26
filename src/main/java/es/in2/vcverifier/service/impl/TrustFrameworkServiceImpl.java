package es.in2.vcverifier.service.impl;

import es.in2.vcverifier.config.ApiConfig;
import es.in2.vcverifier.config.properties.TrustFrameworkProperties;
import es.in2.vcverifier.exception.InvalidSpringProfile;
import es.in2.vcverifier.exception.RemoteFileFetchException;
import es.in2.vcverifier.exception.IssuerOrParticipantIdException;
import es.in2.vcverifier.model.enums.Profile;
import es.in2.vcverifier.service.TrustFrameworkService;
import es.in2.vcverifier.util.Constants;
import lombok.RequiredArgsConstructor;
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
@RequiredArgsConstructor
public class TrustFrameworkServiceImpl implements TrustFrameworkService {
    private final TrustFrameworkProperties trustFrameworkProperties;
    private final ApiConfig apiConfig;

    private static final HttpClient HTTP_CLIENT = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.ALWAYS) // Habilitar seguimiento de redirecciones
            .build();

    @Override
    public String fetchAllowedClient() {
        try {
            return fetchRemoteFile(trustFrameworkProperties.clientsListUri() + getExternalYamlProfile() + Constants.YAML_FILE_SUFFIX);
        } catch (IOException | InterruptedException e) {
            throw new RemoteFileFetchException("Error reading clients list from GitHub.", e);
        }
    }

    private String getExternalYamlProfile() {
        String profile = apiConfig.getCurrentEnvironment();

        if (profile == null) {
            throw new InvalidSpringProfile("Environment variable SPRING_PROFILES_ACTIVE is not set");
        }
        Profile resolvedProfile = Profile.fromString(profile);
        return resolvedProfile.getAbbreviation();
    }

    @Override
    public boolean isIssuerIdAllowed(String issuerId) {
        try {
            List<String> allowedIssuerIds = readRemoteFileAsList(trustFrameworkProperties.issuersListUri()); // Reutiliza el método para obtener la lista
            return allowedIssuerIds.contains(issuerId);
        } catch (IOException | InterruptedException e) {
            throw new IssuerOrParticipantIdException("Error reading issuer ID list from GitHub.", e);
        }
    }

    @Override
    public boolean isParticipantIdAllowed(String participantId) {
        try {
            List<String> allowedParticipantIds = readRemoteFileAsList(trustFrameworkProperties.participantsListUri()); // Reutiliza el método para obtener la lista
            return allowedParticipantIds.contains(participantId);
        } catch (IOException | InterruptedException e) {
            throw new IssuerOrParticipantIdException("Error reading participant ID list from GitHub.", e);
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
            throw new RemoteFileFetchException("Failed to fetch file from GitHub. Status code: " + response.statusCode());
        }
    }
}
