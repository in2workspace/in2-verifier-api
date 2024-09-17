package es.in2.vcverifier.resolver;

import es.in2.vcverifier.service.DIDService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

@Slf4j
@RestController
@RequestMapping("/oidc/did")
@RequiredArgsConstructor
public class ResolverController {

    private final DIDService didService;

    @GetMapping("/{id}")
    public CustomJWKS resolveDid(@PathVariable String id) {
        PublicKey publicKey = didService.getPublicKeyFromDid(id);

        ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
        ECPoint point = ecPublicKey.getW();

        CustomJWKS customJWKS = CustomJWKS.builder()
                .keys(List.of(CustomJWKS.CustomJWK.builder()
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
