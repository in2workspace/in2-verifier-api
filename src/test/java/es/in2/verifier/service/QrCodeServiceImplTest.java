package es.in2.verifier.service;

import es.in2.verifier.model.QrResponse;
import es.in2.verifier.service.impl.QrCodeServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

class QrCodeServiceImplTest {

    private QrCodeService qrCodeService;

    @Mock
    private AuthorizationRequestService authorizationRequestService;

    @BeforeEach
    void setUp() {
        qrCodeService = new QrCodeServiceImpl(authorizationRequestService);
    }

    @Test
    void generateQRCodeReturnsValidQrResponse() {
        String qrText = "Hello, World!";
        Mono<QrResponse> result = qrCodeService.generateQRCode(qrText);

        StepVerifier.create(result)
                .expectNextMatches(qrResponse -> qrResponse.qrCode() != null && !qrResponse.qrCode().isEmpty())
                .verifyComplete();
    }

    @Test
    void generateQRCodeHandlesNullQrText() {
        String qrText = null;
        Mono<QrResponse> result = qrCodeService.generateQRCode(qrText);

        StepVerifier.create(result)
                .expectError(NullPointerException.class)
                .verify();
    }

    @Test
    void generateQRCodeHandlesInvalidQrText() {
        String qrText = "Invalid QR Text with special characters: @#$%^&*()";
        Mono<QrResponse> result = qrCodeService.generateQRCode(qrText);

        StepVerifier.create(result)
                .expectNextMatches(qrResponse -> qrResponse.qrCode() != null && !qrResponse.qrCode().isEmpty())
                .verifyComplete();
    }
}
