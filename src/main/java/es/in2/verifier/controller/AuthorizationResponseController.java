package es.in2.verifier.controller;

import es.in2.verifier.model.AuthorizationRequestQrCode;
import es.in2.verifier.model.AuthorizationResponse;
import es.in2.verifier.service.AuthorizationRequestService;
import es.in2.verifier.service.AuthorizationResponseService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

@Slf4j
@RestController
@RequestMapping("/api/v1/authorization-response")
@RequiredArgsConstructor
public class AuthorizationResponseController {

    public final AuthorizationResponseService authorizationResponseService;

    @PostMapping
    @ResponseStatus(HttpStatus.OK)
    public Mono<AuthorizationRequestQrCode> postAuthorizationResponse(@RequestParam("state") String state,
                                                                      @RequestParam("nonce") String nonce,
                                                                      @RequestParam("scope") String scope,
                                                                      @RequestBody AuthorizationResponse authorizationResponse) {
        log.info("Received authorization response: {}", authorizationResponse);
        log.info("Attributes: state, {}, nonce, {}, scope, {}", state, nonce, scope);
        return null;
    }

}
