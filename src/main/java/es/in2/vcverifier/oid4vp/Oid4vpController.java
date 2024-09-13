package es.in2.vcverifier.oid4vp;

import es.in2.vcverifier.config.CacheStore;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/oid4vp")
@RequiredArgsConstructor
public class Oid4vpController {

    private final CacheStore<String> cacheStoreForJwt; // Inyectamos la caché

    // Este método manejará las solicitudes GET al endpoint
    @GetMapping("/auth-request/{id}")
    public ResponseEntity<String> getJwtFromCache(@PathVariable String id) {
        // Intentamos recuperar el JWT de la caché usando el ID proporcionado
        String jwt = cacheStoreForJwt.get(id);

        if (jwt != null) {
            // Si el JWT existe en la caché, lo devolvemos en la respuesta
            return ResponseEntity.ok(jwt);
        } else {
            // Si no se encuentra el JWT, devolvemos un error 404
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body("JWT not found for id: " + id);
        }
    }
}

