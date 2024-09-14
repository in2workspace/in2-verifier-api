package es.in2.vcverifier.oid4vp.service.impl;

import es.in2.vcverifier.config.CacheStore;
import es.in2.vcverifier.oid4vp.service.AuthorizationResponseProcessorService;
import es.in2.vcverifier.service.VpValidationService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthorizationResponseProcessorServiceImpl implements AuthorizationResponseProcessorService {

    private final CacheStore<String> cacheStore;
    private final VpValidationService vpValidationService; // Service responsible for VP validation

    @Override
    public void processAuthResponse(String state, String vpToken, HttpServletResponse response){
        // Validate if the state exists in the cache
        String redirectUri = cacheStore.get(state);
        if (redirectUri == null) {
            log.error("State {} does not exist in cache", state);
            throw new IllegalStateException("Invalid or expired state");
        }

        // Remove the state from cache after retrieving the redirect URL
        cacheStore.delete(state);
        log.info("State {} has been removed from cache", state);

        // Decode vpToken from Base64
        String decodedVpToken = new String(Base64.getDecoder().decode(vpToken), StandardCharsets.UTF_8);
        log.info("Decoded VP Token: {}", decodedVpToken);

        // Send the decoded token to a service for validation
        boolean isValid = vpValidationService.validateVerifiablePresentation(decodedVpToken);
        if (!isValid) {
            log.error("VP Token is invalid");
            throw new IllegalArgumentException("Invalid VP Token");
        }
        log.info("VP Token validated successfully");

        // Generate a nonce (code)
        String nonce = generateNonce();
        log.info("Nonce generated: {}", nonce);

        // Build the redirect URL with the code (nonce) and the state
        String redirectUrl = UriComponentsBuilder.fromHttpUrl(redirectUri)
                .queryParam("code", nonce)
                .queryParam("state", state)
                .build()
                .toUriString();

        // Perform the redirection using HttpServletResponse
        log.info("Redirecting to URL: {}", redirectUrl);
        try {
            response.sendRedirect(redirectUrl);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    // Method to generate a nonce (code)
    private String generateNonce() {
        return UUID.randomUUID().toString();
    }
}


