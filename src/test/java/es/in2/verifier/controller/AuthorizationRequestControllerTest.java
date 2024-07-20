package es.in2.verifier.controller;

import es.in2.verifier.model.AuthorizationRequestQrCode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

class AuthorizationRequestControllerTest {

    @Mock
    private QrCodeService qrCodeService;

    @InjectMocks
    private AuthorizationRequestController authorizationRequestController;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void getQrCodeReturnsQrResponse() {
        AuthorizationRequestQrCode authorizationRequestQrCode = new AuthorizationRequestQrCode("QR_CODE_DATA");
        when(qrCodeService.generateQRCode(anyString())).thenReturn(Mono.just(authorizationRequestQrCode));

        Mono<AuthorizationRequestQrCode> result = authorizationRequestController.getQrCode();

        StepVerifier.create(result)
                .expectNext(authorizationRequestQrCode)
                .verifyComplete();
    }

    @Test
    void getQrCodeHandlesEmptyResponse() {
        when(qrCodeService.generateQRCode(anyString())).thenReturn(Mono.empty());

        Mono<AuthorizationRequestQrCode> result = authorizationRequestController.getQrCode();

        StepVerifier.create(result)
                .verifyComplete();
    }

    @Test
    void getQrCodeHandlesError() {
        when(qrCodeService.generateQRCode(anyString())).thenReturn(Mono.error(new RuntimeException("Error generating QR code")));

        Mono<AuthorizationRequestQrCode> result = authorizationRequestController.getQrCode();

        StepVerifier.create(result)
                .expectError(RuntimeException.class)
                .verify();
    }

}
