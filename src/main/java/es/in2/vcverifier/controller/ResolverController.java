package es.in2.vcverifier.controller;

import es.in2.vcverifier.model.CustomJWK;
import es.in2.vcverifier.model.CustomJWKS;
import es.in2.vcverifier.service.DIDService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.util.Base64;
import java.util.List;

@Slf4j
@RestController
@RequestMapping("/oidc/did")
@RequiredArgsConstructor
public class ResolverController {

    private final DIDService didService;

    @GetMapping("/{id}")
    @ResponseStatus(HttpStatus.OK)
    public CustomJWKS resolveDid(@PathVariable String id) {
        PublicKey publicKey = didService.getPublicKeyFromDid(id);
        ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
        ECPoint point = ecPublicKey.getW();
        CustomJWKS customJWKS = CustomJWKS.builder()
                .keys(List.of(CustomJWK.builder()
                        .kty("EC")
                        .crv("P-256")
                        .kid(id)
                        .x(Base64.getUrlEncoder().withoutPadding().encodeToString(point.getAffineX().toByteArray()))
                        .y(Base64.getUrlEncoder().withoutPadding().encodeToString(point.getAffineY().toByteArray()))
                        .build()
                ))
                .build();
        log.info("Resolved DID {} to JWK {}", id, customJWKS);
        return customJWKS;
    }

}
