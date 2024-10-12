package es.in2.vcverifier.oid4vp.controller;

import es.in2.vcverifier.exception.QRCodeGenerationException;
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

@ExtendWith(MockitoExtension.class)
class LoginQrControllerTest {

    @InjectMocks
    private LoginQrController loginQrController;

    @Mock
    private Model model;


    @Test
    void showQrLogin_validAuthRequest_shouldReturnLoginView() {
        String authRequest = "validAuthRequest";
        String state = "validState";

        try (MockedStatic<QRCode> qrCodeMock = Mockito.mockStatic(QRCode.class)) {
            qrCodeMock.when(() -> QRCode.from(authRequest)).thenReturn(Mockito.mock(QRCode.class));
            qrCodeMock.when(() -> QRCode.from(authRequest).withSize(250, 250)).thenReturn(Mockito.mock(QRCode.class));
            qrCodeMock.when(() -> QRCode.from(authRequest).withSize(250, 250).stream()).thenReturn(new ByteArrayOutputStream());

            String viewName = loginQrController.showQrLogin(authRequest, state, model);

            assertEquals("login", viewName);

            Mockito.verify(model).addAttribute("qrImage", "data:image/png;base64," + Base64.getEncoder().encodeToString(new ByteArrayOutputStream().toByteArray()));
            Mockito.verify(model).addAttribute("authRequest", authRequest);
            Mockito.verify(model).addAttribute("state", state);
        }
    }

    @Test
    void showQrLogin_exceptionDuringQRCodeGeneration_shouldThrowQRCodeGenerationException() {
        String authRequest = "invalidAuthRequest";
        String state = "validState";

        try (MockedStatic<QRCode> qrCodeMock = Mockito.mockStatic(QRCode.class)) {
            qrCodeMock.when(() -> QRCode.from(authRequest)).thenThrow(new RuntimeException("QR Code Generation Failed"));

            QRCodeGenerationException exception = assertThrows(QRCodeGenerationException.class, () ->
                    loginQrController.showQrLogin(authRequest, state, model)
            );

            assertEquals("QR Code Generation Failed", exception.getMessage());
        }
    }

}