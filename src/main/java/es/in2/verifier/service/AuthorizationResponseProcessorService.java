package es.in2.verifier.service;

public interface AuthorizationResponseProcessorService {
    void processAuthResponse(String state, String vpToken);
}
