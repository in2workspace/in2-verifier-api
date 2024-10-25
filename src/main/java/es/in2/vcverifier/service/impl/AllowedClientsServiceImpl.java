package es.in2.vcverifier.service.impl;

import es.in2.vcverifier.config.properties.ClientRepositoryProperties;
import es.in2.vcverifier.service.AllowedClientsService;
import es.in2.vcverifier.service.HttpClientService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.net.http.HttpResponse;

@Service
@Slf4j
@RequiredArgsConstructor
public class AllowedClientsServiceImpl implements AllowedClientsService {
    private final ClientRepositoryProperties clientRepositoryProperties;
    private final HttpClientService httpClientService;

    @Override
    public String fetchAllowedClient() {
        return fetchRemoteFile(clientRepositoryProperties.uri());
    }

    private String fetchRemoteFile(String fileUrl) {
        HttpResponse<String> response = httpClientService.performGetRequest(fileUrl);
        // Handle the response directly in this method
        return response.body(); // Return the content of the file
    }
}
