package es.in2.verifier.domain.service;

public interface AuthorizationResponseProcessorService {
    void processAuthResponse(String state, String vpToken);
}
