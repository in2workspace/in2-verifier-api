package es.in2.verifier.domain.service;

import es.in2.verifier.domain.exception.PublicKeyDecodingException;
import es.in2.verifier.domain.exception.UnsupportedDIDTypeException;
import es.in2.verifier.domain.service.impl.DIDServiceImpl;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class DIDServiceImplTest {

    @InjectMocks
    private DIDServiceImpl didService;

    @Test
    void getPublicKeyFromValidDid_Success() {
        String validDid = "did:key:zDnaew7Cz5JbZtVGd93qxAjLB1qZEm1eXLPaWEr775R2BZkoY";
        PublicKey publicKey = didService.retrivePublicKeyFromP256DidKey(validDid);
        assertNotNull(publicKey);
    }

    @Test
    void retrivePublicKeyFromDid_UnsupportedDIDKeyTypeException() {
        String invalidDid = "did:example:123456";

        UnsupportedDIDTypeException thrown = assertThrows(UnsupportedDIDTypeException.class, () -> {
            didService.retrivePublicKeyFromP256DidKey(invalidDid);
        });

        assertEquals("Unsupported DID type. Only did:key is supported for the moment.", thrown.getMessage());
    }

    @Test
    void retrivePublicKeyFromDid_PublicKeyDecodingExceptionKey() {
        String invalidDid = "did:key:zInvalidPublicKey";

        PublicKeyDecodingException thrown = assertThrows(PublicKeyDecodingException.class, () -> {
            didService.retrivePublicKeyFromP256DidKey(invalidDid);
        });

        assertEquals("JWT signature verification failed.", thrown.getMessage());
    }
}
