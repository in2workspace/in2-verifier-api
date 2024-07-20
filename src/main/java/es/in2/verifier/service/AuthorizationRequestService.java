package es.in2.verifier.service;

import reactor.core.publisher.Mono;

public interface AuthorizationRequestService {
    Mono<String> generateAuthorizationRequest();
}
