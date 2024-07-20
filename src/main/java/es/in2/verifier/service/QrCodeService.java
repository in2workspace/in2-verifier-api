package es.in2.verifier.service;

import es.in2.verifier.model.QrResponse;
import reactor.core.publisher.Mono;

public interface QrCodeService {
    Mono<QrResponse> generateQRCode(String text);
}
