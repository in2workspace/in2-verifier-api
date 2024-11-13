package es.in2.verifier.resolver;

import es.in2.verifier.infrastructure.controller.ResolverController;
import es.in2.verifier.domain.service.DIDService;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.web.servlet.MockMvc;

import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;

import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(ResolverController.class)
@AutoConfigureMockMvc(addFilters = false)  // Disable security filters for the test
class ResolverControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private DIDService didService;

    @Test
    void testResolveDid() throws Exception {
        // Mock a public EC key
        ECPublicKey mockPublicKey = mock(ECPublicKey.class);
        ECPoint mockECPoint = new ECPoint(new BigInteger("12345"), new BigInteger("67890"));
        Mockito.when(mockPublicKey.getW()).thenReturn(mockECPoint);
        Mockito.when(didService.getPublicKeyFromDid("test-id")).thenReturn(mockPublicKey);

        // Perform GET request and verify response
        mockMvc.perform(get("/oidc/did/test-id"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys[0].kty").value("EC"))
                .andExpect(jsonPath("$.keys[0].crv").value("P-256"))
                .andExpect(jsonPath("$.keys[0].kid").value("test-id"))
                .andExpect(jsonPath("$.keys[0].x").exists())
                .andExpect(jsonPath("$.keys[0].y").exists());

        // Verify interactions with the service
        verify(didService, times(1)).getPublicKeyFromDid("test-id");
    }

}
