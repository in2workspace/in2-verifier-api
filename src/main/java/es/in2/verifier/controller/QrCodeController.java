package es.in2.verifier.controller;

import es.in2.verifier.model.QrResponse;
import es.in2.verifier.service.QrCodeService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api/v1/qr")
@RequiredArgsConstructor
public class QrCodeController {

    public final QrCodeService qrCodeService;

    @GetMapping
    @ResponseStatus(HttpStatus.OK)
    public Mono<QrResponse> getQrCode() {
        String qrContent = "Default text";
        return qrCodeService.generateQRCode(qrContent);
    }

}
