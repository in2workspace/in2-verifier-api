package es.in2.vcverifier.oid4vp.service;

import jakarta.servlet.http.HttpServletResponse;

public interface AuthorizationResponseProcessorService {
    void processAuthResponse(String state, String vpToken, HttpServletResponse response);
}
