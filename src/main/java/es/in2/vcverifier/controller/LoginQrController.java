package es.in2.vcverifier.controller;

import es.in2.vcverifier.config.properties.SecurityProperties;
import es.in2.vcverifier.config.properties.VerifierUiLoginUrisProperties;
import es.in2.vcverifier.exception.QRCodeGenerationException;
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

@Controller
@RequiredArgsConstructor
public class LoginQrController {

    private final VerifierUiLoginUrisProperties verifierUiLoginUrisProperties;
    private final SecurityProperties securityProperties;

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
            model.addAttribute("onboardingUri", verifierUiLoginUrisProperties.onboardingUri());
            model.addAttribute("supportUri", verifierUiLoginUrisProperties.supportUri());
            model.addAttribute("walletUri", verifierUiLoginUrisProperties.walletUri());
            model.addAttribute("cronUnit", securityProperties.loginCode().expirationProperties().cronUnit());
            model.addAttribute("expiration", securityProperties.loginCode().expirationProperties().expiration());
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
