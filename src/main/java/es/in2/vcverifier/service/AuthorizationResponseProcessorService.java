package es.in2.vcverifier.service;

public interface AuthorizationResponseProcessorService {
    void processAuthResponse(String state, String vpToken);
}
