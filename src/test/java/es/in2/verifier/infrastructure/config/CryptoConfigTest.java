package es.in2.verifier.infrastructure.config;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import es.in2.verifier.domain.exception.ECKeyCreationException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CryptoConfigTest {

    @Mock
    private ApplicationConfig applicationConfig;

    @InjectMocks
    private CryptoConfig cryptoConfig;

    @Test
    void getECKeyReturnsValidECKey() {
        when(applicationConfig.getPrivateKey()).thenReturn("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");

        ECKey ecKey = cryptoConfig.getECKey();

        assertNotNull(ecKey);
        assertEquals(Curve.P_256, ecKey.getCurve());
        assertEquals("did:key:z", ecKey.getKeyID().substring(0, 9));
    }

    @Test
    void getECKeyThrowsECKeyCreationExceptionForInvalidPrivateKey() {
        when(applicationConfig.getPrivateKey()).thenReturn("invalid_key");

        assertThrows(ECKeyCreationException.class, () -> cryptoConfig.getECKey());
    }

    @Test
    void convertRawKeyToMultiBase58BtcReturnsValidBase58String() {
        byte[] publicKey = new byte[]{1, 2, 3, 4, 5};
        int code = 0x1200;

        String base58String = cryptoConfig.convertRawKeyToMultiBase58Btc(publicKey, code);

        assertNotNull(base58String);
        assertFalse(base58String.isEmpty());
    }
}