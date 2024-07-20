package es.in2.verifier.model;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class QrResponseTest {

    @Test
    void qrResponseBuilderCreatesInstance() {
        QrResponse qrResponse = QrResponse.builder().qrCode("QR_CODE_DATA").build();
        assertNotNull(qrResponse);
    }

    @Test
    void qrResponseBuilderSetsQrCode() {
        QrResponse qrResponse = QrResponse.builder().qrCode("QR_CODE_DATA").build();
        assertEquals("QR_CODE_DATA", qrResponse.qrCode());
    }

    @Test
    void qrResponseHandlesNullQrCode() {
        QrResponse qrResponse = QrResponse.builder().qrCode(null).build();
        assertEquals(null, qrResponse.qrCode());
    }

}
