package es.in2.vcverifier.service.impl;

import es.in2.vcverifier.config.ApiConfig;
import es.in2.vcverifier.config.properties.ClientRepositoryProperties;
import es.in2.vcverifier.exception.InvalidSpringProfile;
import es.in2.vcverifier.model.enums.Profile;
import es.in2.vcverifier.service.AllowedClientsService;
import es.in2.vcverifier.service.HttpClientService;
import es.in2.vcverifier.util.Constants;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.net.http.HttpResponse;

@Service
@Slf4j
@RequiredArgsConstructor
public class AllowedClientsServiceImpl implements AllowedClientsService {
    private final ClientRepositoryProperties clientRepositoryProperties;
    private final ApiConfig apiConfig;
    private final HttpClientService httpClientService;

    @Override
    public String fetchAllowedClient() {
        return fetchRemoteFile(clientRepositoryProperties.uri() + getExternalYamlProfile() + Constants.YAML_FILE_SUFFIX);
    }

    private String getExternalYamlProfile() {
        String profile = apiConfig.getCurrentEnvironment();

        if (profile == null || profile.isBlank()) {
            throw new InvalidSpringProfile("Environment variable SPRING_PROFILES_ACTIVE is not set");
        }
        Profile resolvedProfile = Profile.fromString(profile);
        return resolvedProfile.getAbbreviation();
    }

    private String fetchRemoteFile(String fileUrl) {
        HttpResponse<String> response = httpClientService.performGetRequest(fileUrl);
        // Handle the response directly in this method
        return response.body(); // Return the content of the file
    }

}
