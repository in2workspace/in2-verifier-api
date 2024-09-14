package es.in2.vcverifier.oid4vp.controller;

import net.glxn.qrgen.javase.QRCode;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.ByteArrayOutputStream;
import java.util.Base64;

@Controller
@RequestMapping("/login")
public class LoginQrController {

    @GetMapping("/qr")
    public String showQrLogin(@RequestParam("authRequest") String authRequest, Model model) {
        try {
            // Generar la imagen QR en base64
            String qrImageBase64 = generateQRCodeImageBase64(authRequest);

            // Pasar el QR en base64 y el authRequest en texto al modelo
            model.addAttribute("qrImage", "data:image/png;base64," + qrImageBase64);
            model.addAttribute("authRequest", authRequest);

        } catch (Exception e) {
            throw new RuntimeException();
        }

        return "qr-page";
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

