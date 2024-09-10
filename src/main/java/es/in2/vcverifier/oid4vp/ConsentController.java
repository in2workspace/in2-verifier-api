package es.in2.vcverifier.oid4vp;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.security.Principal;

@Controller
public class ConsentController {

    @GetMapping("/oidc/consent")
    public String showConsentPage(HttpServletRequest request, Model model) {

        // Aquí puedes agregar cualquier otro dato necesario para el consentimiento
        return "consent-page"; // El nombre de la vista que muestra el QR y solicita el consentimiento
    }

    private String generateQRCode(String authorizationRequest) {

        // Lógica para generar el código QR
        String qrCodeData = null;
        return qrCodeData;
    }

}
