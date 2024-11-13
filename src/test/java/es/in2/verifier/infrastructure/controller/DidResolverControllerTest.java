package es.in2.verifier.infrastructure.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import es.in2.verifier.application.workflow.DidResolverWorkflow;
import es.in2.verifier.domain.exception.NotSupportedDidException;
import es.in2.verifier.domain.model.dto.CustomJWK;
import es.in2.verifier.domain.model.dto.CustomJWKS;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(DidResolverController.class)
@AutoConfigureMockMvc(addFilters = false)  // Disable security filters for the test
class DidResolverControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private DidResolverWorkflow didResolverWorkflow;

    @BeforeEach
    public void setUp() {
        objectMapper.configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);
    }

    @Test
    void resolveDidWithValidId() throws Exception {
        // Arrange
        CustomJWKS expectedResponse = new CustomJWKS(List.of(new CustomJWK("EC", "P-256", "did:key:zDn123", "ew", "gA")));
        Mockito.when(didResolverWorkflow.resolveDid("did:key:zDn123")).thenReturn(expectedResponse);
        String expectedJson = objectMapper.writeValueAsString(expectedResponse);
        // Act & Assert
        mockMvc.perform(get("/oidc/did/did:key:zDn123"))
                .andExpect(status().isOk())
                .andExpect(content().json(expectedJson));

        verify(didResolverWorkflow, times(1)).resolveDid("did:key:zDn123");
    }

    @Test
    void resolveDidWithInvalidIdThrowsException() throws Exception {
        Mockito.when(didResolverWorkflow.resolveDid("invalid-id")).thenThrow(new NotSupportedDidException("Invalid DID"));

        mockMvc.perform(get("/oidc/did/invalid-id"))
                .andExpect(status().isBadRequest());

        verify(didResolverWorkflow, times(1)).resolveDid("invalid-id");
    }

    @Test
    void resolveDidWithNullIdThrowsException() throws Exception {
        mockMvc.perform(get("/oidc/did/"))
                .andExpect(status().isNotFound());
    }

}
