package es.in2.verifier.model;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class AuthorizationRequestQrCodeTest {

    @Test
    void qrResponseBuilderCreatesInstance() {
        AuthorizationRequestQrCode authorizationRequestQrCode = AuthorizationRequestQrCode.builder().qrCode("QR_CODE_DATA").build();
        assertNotNull(authorizationRequestQrCode);
    }

    @Test
    void qrResponseBuilderSetsQrCode() {
        AuthorizationRequestQrCode authorizationRequestQrCode = AuthorizationRequestQrCode.builder().qrCode("QR_CODE_DATA").build();
        assertEquals("QR_CODE_DATA", authorizationRequestQrCode.qrCode());
    }

    @Test
    void qrResponseHandlesNullQrCode() {
        AuthorizationRequestQrCode authorizationRequestQrCode = AuthorizationRequestQrCode.builder().qrCode(null).build();
        assertEquals(null, authorizationRequestQrCode.qrCode());
    }

}
