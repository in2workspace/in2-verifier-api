package es.in2.verifier.infrastructure.controller;

import es.in2.verifier.application.workflow.DidResolverWorkflow;
import es.in2.verifier.domain.model.dto.CustomJWK;
import es.in2.verifier.domain.model.dto.CustomJWKS;
import es.in2.verifier.domain.service.DIDService;
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
public class DidResolverController {

    private final DidResolverWorkflow didResolverWorkflow;

    @GetMapping("/{id}")
    @ResponseStatus(HttpStatus.OK)
    public CustomJWKS resolveDid(@PathVariable String id) {
        log.info("Resolving DID: {}", id);
        return didResolverWorkflow.resolveDid(id);
    }

}
