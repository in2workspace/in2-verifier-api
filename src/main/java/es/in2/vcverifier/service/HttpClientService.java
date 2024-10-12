package es.in2.vcverifier.service;

import java.net.http.HttpResponse;

public interface HttpClientService {
    HttpResponse<String> performGetRequest(String url);
}
