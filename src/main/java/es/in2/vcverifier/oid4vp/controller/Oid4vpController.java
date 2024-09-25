package es.in2.vcverifier.oid4vp.controller;

import es.in2.vcverifier.config.CacheStore;
import es.in2.vcverifier.exception.ResourceNotFoundException;
import es.in2.vcverifier.model.AuthorizationRequestJWT;
import es.in2.vcverifier.oid4vp.service.AuthorizationResponseProcessorService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/oid4vp")
@RequiredArgsConstructor
public class Oid4vpController {

    private final CacheStore<AuthorizationRequestJWT> cacheStoreForAuthorizationRequestJWT;
    private final AuthorizationResponseProcessorService authorizationResponseProcessorService;

    // Este método manejará las solicitudes GET al endpoint
    @GetMapping("/auth-request/{id}")
    @ResponseStatus(HttpStatus.OK)
    public String getAuthorizationRequest(@PathVariable String id) {
        // Intentamos recuperar el JWT de la caché usando el ID proporcionado
        AuthorizationRequestJWT authorizationRequestJWT = cacheStoreForAuthorizationRequestJWT.get(id);
        cacheStoreForAuthorizationRequestJWT.delete(id);
        String jwt = authorizationRequestJWT.authRequest();

        if (jwt != null) {
            return jwt;
        } else {
            throw new ResourceNotFoundException("JWT not found for id: " + id);
        }
    }

    @PostMapping("/auth-response")
    @ResponseStatus(HttpStatus.OK)
    public void processAuthResponse(
            @RequestParam("state") String state,
            @RequestParam("vp_token") String vpToken,
            @RequestParam(value = "presentation_submission", required = false) String presentationSubmission,
            HttpServletResponse response) {
        //TODO We need use presentationSubmission in the future
        authorizationResponseProcessorService.processAuthResponse(state, vpToken, response);
    }
}

