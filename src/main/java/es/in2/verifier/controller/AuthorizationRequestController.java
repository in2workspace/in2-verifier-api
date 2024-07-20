package es.in2.verifier.controller;

import es.in2.verifier.model.AuthorizationRequestQrCode;
import es.in2.verifier.service.AuthorizationRequestService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api/v1/authorization-request")
@RequiredArgsConstructor
public class AuthorizationRequestController {

    public final AuthorizationRequestService authorizationRequestService;

    @GetMapping
    @ResponseStatus(HttpStatus.OK)
    public Mono<AuthorizationRequestQrCode> getQrCode() {
        return authorizationRequestService.generateAuthorizationRequest();
    }

}
