package es.in2.vcverifier.oid4vp;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class ConsentController {

    @GetMapping("/oauth2/v1/h2m/authorize")
    public String showConsentPage(HttpServletRequest request, Model model) {
        // Recuperar el objeto de solicitud de autorización desde la sesión
        String authorizationRequest = (String) request.getSession().getAttribute("authorizationRequest");

        // Generar el código QR a partir del authorizationRequest
        String qrCode = generateQRCode(authorizationRequest);

        // Pasar el código QR al modelo para renderizarlo en la vista
        model.addAttribute("qrCode", qrCode);

        // Aquí puedes agregar cualquier otro dato necesario para el consentimiento
        return "consent-page"; // El nombre de la vista que muestra el QR y solicita el consentimiento
    }

    private String generateQRCode(String authorizationRequest) {

        // Lógica para generar el código QR
        String qrCodeData = null;
        return qrCodeData;
    }

}
