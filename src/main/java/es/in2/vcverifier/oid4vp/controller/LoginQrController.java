package es.in2.vcverifier.oid4vp.controller;

import es.in2.vcverifier.config.properties.VerifierUiLoginUrisProperties;
import es.in2.vcverifier.exception.QRCodeGenerationException;
import lombok.RequiredArgsConstructor;
import net.glxn.qrgen.javase.QRCode;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.io.ByteArrayOutputStream;
import java.util.Base64;

@Controller
@RequiredArgsConstructor
public class LoginQrController {

    private final VerifierUiLoginUrisProperties verifierUiLoginUrisProperties;


    @GetMapping("/login")
    @ResponseStatus(HttpStatus.OK)
    public String showQrLogin(@RequestParam("authRequest") String authRequest, @RequestParam("state") String state, Model model) {
        try {
            // Generar la imagen QR en base64
            String qrImageBase64 = generateQRCodeImageBase64(authRequest);

            // Pasar el QR en base64 y el authRequest en texto al modelo
            model.addAttribute("qrImage", "data:image/png;base64," + qrImageBase64);
            model.addAttribute("authRequest", authRequest);
            // Pasar el sessionId al modelo
            model.addAttribute("state", state);

            model.addAttribute("onboardingUri", verifierUiLoginUrisProperties.onboardingUri());
            model.addAttribute("supportUri", verifierUiLoginUrisProperties.supportUri());
            model.addAttribute("walletUri", verifierUiLoginUrisProperties.walletUri());

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

