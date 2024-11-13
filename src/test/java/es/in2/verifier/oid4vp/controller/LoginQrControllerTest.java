package es.in2.verifier.oid4vp.controller;

import es.in2.verifier.domain.exception.QRCodeGenerationException;
import es.in2.verifier.infrastructure.config.ApplicationConfig;
import es.in2.verifier.infrastructure.controller.LoginQrController;
import net.glxn.qrgen.javase.QRCode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.ui.Model;

import java.io.ByteArrayOutputStream;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class LoginQrControllerTest {

    @InjectMocks
    private LoginQrController loginQrController;

    @Mock
    private Model model;

    @Mock
    private ApplicationConfig applicationConfig;

    @Test
    void showQrLogin_validAuthRequest_shouldReturnLoginView() {
        String authRequest = "validAuthRequest";
        String state = "validState";
        when(applicationConfig.getLoginPageOnboardingGuideUrl()).thenReturn("onboardingUri");
        when(applicationConfig.getLoginPageUserSupportUrl()).thenReturn("supportUri");
        when(applicationConfig.getLoginPageWalletUrl()).thenReturn("walletUri");
        when(applicationConfig.getQRCodeExpiration()).thenReturn(10L);
        try (MockedStatic<QRCode> qrCodeMock = Mockito.mockStatic(QRCode.class)) {
            qrCodeMock.when(() -> QRCode.from(authRequest)).thenReturn(Mockito.mock(QRCode.class));
            qrCodeMock.when(() -> QRCode.from(authRequest).withSize(250, 250)).thenReturn(Mockito.mock(QRCode.class));
            qrCodeMock.when(() -> QRCode.from(authRequest).withSize(250, 250).stream()).thenReturn(new ByteArrayOutputStream());
            String viewName = loginQrController.showQrLogin(authRequest, state, model, "homeUri");
            assertEquals("login", viewName);
            Mockito.verify(model).addAttribute("qrImage", "data:image/png;base64," + Base64.getEncoder().encodeToString(new ByteArrayOutputStream().toByteArray()));
            Mockito.verify(model).addAttribute("authRequest", authRequest);
            Mockito.verify(model).addAttribute("state", state);
            Mockito.verify(model).addAttribute("homeUri", "homeUri");
            Mockito.verify(model).addAttribute("expiration", "10");
            Mockito.verify(model).addAttribute("cronUnit", "MINUTES");
        }
    }

    @Test
    void showQrLogin_exceptionDuringQRCodeGeneration_shouldThrowQRCodeGenerationException() {
        String authRequest = "invalidAuthRequest";
        String state = "validState";

        try (MockedStatic<QRCode> qrCodeMock = Mockito.mockStatic(QRCode.class)) {
            qrCodeMock.when(() -> QRCode.from(authRequest)).thenThrow(new RuntimeException("QR Code Generation Failed"));

            QRCodeGenerationException exception = assertThrows(QRCodeGenerationException.class, () ->
                    loginQrController.showQrLogin(authRequest, state, model, "homeUri")
            );

            assertEquals("QR Code Generation Failed", exception.getMessage());
        }
    }

}