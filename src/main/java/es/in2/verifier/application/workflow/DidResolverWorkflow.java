package es.in2.verifier.application.workflow;

import es.in2.verifier.domain.model.dto.CustomJWKS;

public interface DidResolverWorkflow {
    CustomJWKS resolveDid(String did);
}
