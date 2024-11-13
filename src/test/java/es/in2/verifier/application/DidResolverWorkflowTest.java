package es.in2.verifier.application;

import es.in2.verifier.application.workflow.impl.DidResolverWorkflowImpl;
import es.in2.verifier.domain.exception.NotSupportedDidException;
import es.in2.verifier.domain.model.dto.CustomJWK;
import es.in2.verifier.domain.model.dto.CustomJWKS;
import es.in2.verifier.domain.service.DIDService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DidResolverWorkflowImplTest {

    @Mock
    private DIDService didService;

    @InjectMocks
    private DidResolverWorkflowImpl didResolverWorkflow;

    @Test
    void resolveDidWithValidDid() {
        // Arrange
        String did = "did:key:zDn123";
        ECPublicKey ecPublicKey = mock(ECPublicKey.class);
        ECPoint point = new ECPoint(new BigInteger("123"), new BigInteger("456"));
        when(ecPublicKey.getW()).thenReturn(point);
        when(didService.retrivePublicKeyFromP256DidKey(did)).thenReturn(ecPublicKey);
        // Act
        CustomJWKS result = didResolverWorkflow.resolveDid(did);
        // Assert
        assertNotNull(result);
        assertEquals(1, result.keys().size());
        CustomJWK jwk = result.keys().get(0);
        assertEquals("EC", jwk.kty());
        assertEquals("P-256", jwk.crv());
        assertEquals(did, jwk.kid());
        assertEquals("ew", jwk.x());
        assertEquals("Acg", jwk.y());
    }

    @Test
    void resolveDidWithInvalidDidThrowsException() {
        String did = "did:key:invalid";
        assertThrows(NotSupportedDidException.class, () -> didResolverWorkflow.resolveDid(did));
    }

}
