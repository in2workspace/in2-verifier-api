package es.in2.verifier.service;

import es.in2.verifier.model.AuthorizationRequestQrCode;
import reactor.core.publisher.Mono;

public interface AuthorizationRequestService {
    Mono<AuthorizationRequestQrCode> generateAuthorizationRequest();
}
