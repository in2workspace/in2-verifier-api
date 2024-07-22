package es.in2.verifier.service.impl;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import es.in2.verifier.config.ApplicationConfig;
import es.in2.verifier.config.CacheStoreConfig;
import es.in2.verifier.model.AuthorizationRequestQrCode;
import es.in2.verifier.service.AuthorizationRequestService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.io.ByteArrayOutputStream;
import java.util.Base64;

import static es.in2.verifier.util.ApplicationUtils.generateCustomNonce;

@Service
@RequiredArgsConstructor
public class AuthorizationRequestServiceImpl implements AuthorizationRequestService {

    private static final String RESPONSE_TYPE = "vp_token";
    private static final String RESPONSE_MODE = "direct_post";
    private static final String LOGIN_SCOPE = "LearCredentialEmployee";
    private final ApplicationConfig applicationConfig;
    private final CacheStoreConfig cacheStoreConfig;

    @Override
    public Mono<AuthorizationRequestQrCode> generateAuthorizationRequest() {
        return buildAuthorizationRequest()
                .flatMap(this::generateQRCode);
    }

    private Mono<String> buildAuthorizationRequest() {
        String authorizationRequestTemplate = "/authorize?" +
                "response_type=%s" +
                "&response_mode=%s" +
                "&client_id=%s" +
                "&redirect_uri=%s";
        String redirectUriTemplate = "%s%s?state=%s&nonce=%s&scope=%s";
        return generateState()
                .flatMap(state -> generateNonce()
                        .flatMap(nonce -> {
                            final String redirectUri = String.format(redirectUriTemplate,
                                    applicationConfig.getExternalDomain(),
                                    applicationConfig.getAuthorizationResponsePath(),
                                    state,
                                    nonce,
                                    LOGIN_SCOPE); // todo: scope is requested to Credential Config Service
                            return Mono.just(String.format(authorizationRequestTemplate,
                                    RESPONSE_TYPE,
                                    RESPONSE_MODE,
                                    applicationConfig.getClientId(),
                                    redirectUri));
                        }));
    }

    private Mono<AuthorizationRequestQrCode> generateQRCode(String qrText) {
        QRCodeWriter qrCodeWriter = new QRCodeWriter();
        int matrixWidth = 200;
        int matrixHeight = 200;
        try {
            BitMatrix bitMatrix = qrCodeWriter.encode(qrText, BarcodeFormat.QR_CODE, matrixWidth, matrixHeight);
            ByteArrayOutputStream pngOutputStream = new ByteArrayOutputStream();
            MatrixToImageWriter.writeToStream(bitMatrix, "PNG", pngOutputStream);
            byte[] pngData = pngOutputStream.toByteArray();
            return Mono.just(AuthorizationRequestQrCode.builder().qrCode(Base64.getEncoder().encodeToString(pngData)).build());
        } catch (Exception e) {
            return Mono.error(e);
        }
    }

    private Mono<String> generateState() {
        return generateCustomNonce()
                .flatMap(result -> cacheStoreConfig.cacheStore().add("state", result)
                        .then(Mono.just(result)));
    }

    private Mono<String> generateNonce() {
        return generateCustomNonce()
                .flatMap(result -> cacheStoreConfig.cacheStore().add("nonce", result)
                        .then(Mono.just(result)));
    }

}
