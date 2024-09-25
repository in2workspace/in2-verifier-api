package es.in2.vcverifier.oid4vp.controller;

import es.in2.vcverifier.config.CacheStore;
import es.in2.vcverifier.model.AuthorizationRequestJWT;
import es.in2.vcverifier.oid4vp.service.AuthorizationResponseProcessorService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
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
    public ResponseEntity<String> getAuthorizationRequest(@PathVariable String id) {
        // Intentamos recuperar el JWT de la caché usando el ID proporcionado
        AuthorizationRequestJWT authorizationRequestJWT = cacheStoreForAuthorizationRequestJWT.get(id);
        cacheStoreForAuthorizationRequestJWT.delete(id);
        String jwt = authorizationRequestJWT.authRequest();

        if (jwt != null) {
            // Si el JWT existe en la caché, lo devolvemos en la respuesta
            return ResponseEntity.ok(jwt);
        } else {
            // Si no se encuentra el JWT, devolvemos un error 404
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body("JWT not found for id: " + id);
        }
    }

    @PostMapping("/auth-response")
    @ResponseStatus(HttpStatus.OK)
    public ResponseEntity<Void> processAuthResponse(
            @RequestParam("state") String state,
            @RequestParam("vp_token") String vpToken,
            @RequestParam(value = "presentation_submission", required = false) String presentationSubmission,
            HttpServletResponse response) {

        authorizationResponseProcessorService.processAuthResponse(state, vpToken, response);

        return ResponseEntity.ok().build();
    }
}

