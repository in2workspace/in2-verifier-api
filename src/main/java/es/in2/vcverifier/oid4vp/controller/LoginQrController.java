package es.in2.vcverifier.oid4vp.controller;

import es.in2.vcverifier.exception.QRCodeGenerationException;
import net.glxn.qrgen.javase.QRCode;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.io.ByteArrayOutputStream;
import java.util.Base64;

@Controller
public class LoginQrController {


    @GetMapping("/login")
    @ResponseStatus(HttpStatus.OK)
    public String showQrLogin(@RequestParam("authRequest") String authRequest, Model model) {
        try {
            // Generar la imagen QR en base64
            String qrImageBase64 = generateQRCodeImageBase64(authRequest);

            // Pasar el QR en base64 y el authRequest en texto al modelo
            model.addAttribute("qrImage", "data:image/png;base64," + qrImageBase64);
            model.addAttribute("authRequest", authRequest);

        } catch (Exception e) {
            throw new QRCodeGenerationException(e.getMessage());
        }

        return "login";
    }

    private String generateQRCodeImageBase64(String barcodeText){
        ByteArrayOutputStream stream = QRCode
                .from(barcodeText)
                .withSize(250, 250)
                .stream();

        byte[] imageBytes = stream.toByteArray();
        return Base64.getEncoder().encodeToString(imageBytes);
    }

}

