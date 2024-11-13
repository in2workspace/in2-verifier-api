package es.in2.verifier.application.workflow.impl;

import es.in2.verifier.application.workflow.DidResolverWorkflow;
import es.in2.verifier.domain.exception.NotSupportedDidException;
import es.in2.verifier.domain.model.dto.CustomJWK;
import es.in2.verifier.domain.model.dto.CustomJWKS;
import es.in2.verifier.domain.service.DIDService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.util.Base64;
import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class DidResolverWorkflowImpl implements DidResolverWorkflow {

    private final DIDService didService;

    @Override
    public CustomJWKS resolveDid(String did) {
        checkDidValidity(did);
        ECPublicKey ecPublicKey = (ECPublicKey) didService.retrivePublicKeyFromP256DidKey(did);
        ECPoint point = ecPublicKey.getW();
        CustomJWKS customJWKS = CustomJWKS.builder()
                .keys(List.of(CustomJWK.builder()
                        .kty("EC")
                        .crv("P-256")
                        .kid(did)
                        .x(Base64.getUrlEncoder().withoutPadding().encodeToString(point.getAffineX().toByteArray()))
                        .y(Base64.getUrlEncoder().withoutPadding().encodeToString(point.getAffineY().toByteArray()))
                        .build()
                ))
                .build();
        log.info("DID {} resolved. JWK Data: {}", did, customJWKS);
        return customJWKS;
    }

    private void checkDidValidity(String did) {
        if (!did.startsWith("did:key:zDn")) {
            throw new NotSupportedDidException("Only did:key which starts with 'zDn' are supported");
        }
    }

}
