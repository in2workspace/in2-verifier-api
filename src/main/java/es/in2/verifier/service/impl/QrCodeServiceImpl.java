package es.in2.verifier.service.impl;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import es.in2.verifier.model.QrResponse;
import es.in2.verifier.service.AuthorizationRequestService;
import es.in2.verifier.service.QrCodeService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.io.ByteArrayOutputStream;
import java.util.Base64;

@Service
@RequiredArgsConstructor
public class QrCodeServiceImpl implements QrCodeService {

    private final AuthorizationRequestService authorizationRequestService;

    @Override
    public Mono<QrResponse> generateQRCode(String qrText) {
        QRCodeWriter qrCodeWriter = new QRCodeWriter();
        int matrixWidth = 200;
        int matrixHeight = 200;
        return authorizationRequestService.generateAuthorizationRequest()
                .flatMap(result -> {
                    try {
                        BitMatrix bitMatrix = qrCodeWriter.encode(result, BarcodeFormat.QR_CODE, matrixWidth, matrixHeight);
                        ByteArrayOutputStream pngOutputStream = new ByteArrayOutputStream();
                        MatrixToImageWriter.writeToStream(bitMatrix, "PNG", pngOutputStream);
                        byte[] pngData = pngOutputStream.toByteArray();
                        return Mono.just(QrResponse.builder().qrCode(Base64.getEncoder().encodeToString(pngData)).build());
                    } catch (Exception e) {
                        return Mono.error(e);
                    }
                });
    }

}
