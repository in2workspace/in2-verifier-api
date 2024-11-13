package es.in2.verifier.infrastructure.controller;

import es.in2.verifier.domain.exception.QRCodeGenerationException;
import es.in2.verifier.infrastructure.config.ApplicationConfig;
import lombok.RequiredArgsConstructor;
import net.glxn.qrgen.javase.QRCode;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;

import java.io.ByteArrayOutputStream;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

@Controller
@RequiredArgsConstructor
public class LoginQrController {

    private final ApplicationConfig applicationConfig;

    @GetMapping("/login")
    @ResponseStatus(HttpStatus.OK)
    public String showQrLogin(@RequestParam("authRequest") String authRequest, @RequestParam("state") String state, Model model, @RequestParam("homeUri") String homeUri) {
        try {
            // Generar la imagen QR en base64
            String qrImageBase64 = generateQRCodeImageBase64(authRequest);
            // Pasar el QR en base64 y el authRequest en texto al modelo
            model.addAttribute("qrImage", "data:image/png;base64," + qrImageBase64);
            model.addAttribute("authRequest", authRequest);
            // Pasar el sessionId al modelo
            model.addAttribute("state", state);
            model.addAttribute("homeUri", homeUri);
            model.addAttribute("onboardingUri", applicationConfig.getLoginPageOnboardingGuideUrl());
            model.addAttribute("supportUri", applicationConfig.getLoginPageUserSupportUrl());
            model.addAttribute("walletUri", applicationConfig.getLoginPageWalletUrl());
            model.addAttribute("cronUnit", String.valueOf(TimeUnit.MINUTES));
            model.addAttribute("expiration", String.valueOf(applicationConfig.getQRCodeExpiration()));
        } catch (Exception e) {
            throw new QRCodeGenerationException(e.getMessage());
        }
        return "login";
    }

    private String generateQRCodeImageBase64(String barcodeText) {
        ByteArrayOutputStream stream = QRCode
                .from(barcodeText)
                .withSize(250, 250)
                .stream();
        byte[] imageBytes = stream.toByteArray();
        return Base64.getEncoder().encodeToString(imageBytes);
    }

}
