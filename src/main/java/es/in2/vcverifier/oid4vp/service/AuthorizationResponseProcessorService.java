package es.in2.vcverifier.oid4vp.service;

public interface AuthorizationResponseProcessorService {
    void processAuthResponse(String state, String vpToken);
}
