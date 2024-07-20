package es.in2.verifier.controller;

import es.in2.verifier.model.QrResponse;
import es.in2.verifier.service.QrCodeService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

class QrCodeControllerTest {

    @Mock
    private QrCodeService qrCodeService;

    @InjectMocks
    private QrCodeController qrCodeController;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void getQrCodeReturnsQrResponse() {
        QrResponse qrResponse = new QrResponse("QR_CODE_DATA");
        when(qrCodeService.generateQRCode(anyString())).thenReturn(Mono.just(qrResponse));

        Mono<QrResponse> result = qrCodeController.getQrCode();

        StepVerifier.create(result)
                .expectNext(qrResponse)
                .verifyComplete();
    }

    @Test
    void getQrCodeHandlesEmptyResponse() {
        when(qrCodeService.generateQRCode(anyString())).thenReturn(Mono.empty());

        Mono<QrResponse> result = qrCodeController.getQrCode();

        StepVerifier.create(result)
                .verifyComplete();
    }

    @Test
    void getQrCodeHandlesError() {
        when(qrCodeService.generateQRCode(anyString())).thenReturn(Mono.error(new RuntimeException("Error generating QR code")));

        Mono<QrResponse> result = qrCodeController.getQrCode();

        StepVerifier.create(result)
                .expectError(RuntimeException.class)
                .verify();
    }

}
