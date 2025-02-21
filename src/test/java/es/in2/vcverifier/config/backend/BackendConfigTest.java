package es.in2.vcverifier.config.backend;

import es.in2.vcverifier.config.properties.BackendProperties;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(classes = {BackendConfigImpl.class, BackendConfigTest.TestConfig.class})
@ActiveProfiles("test")
@TestPropertySource(properties = {
        "verifier.backend.url=https://backend.example.com",
        "verifier.backend.identity.privateKey=0x123456789abcdef",
        "verifier.backend.trustFrameworks[0].trustedIssuersListUrl.uri=https://trust.example.com/issuers",
        "verifier.backend.trustFrameworks[0].trustedServicesListUrl.uri=https://trust.example.com/services",
        "verifier.backend.trustFrameworks[0].revokedCredentialListUrl.uri=https://trust.example.com/revoked"
})
class BackendConfigTest {

    @Autowired
    private BackendConfig backendConfig;

    @Test
    void testBackendConfig() {
        assertThat(backendConfig.getUrl())
                .as("Backend URL should match")
                .isEqualTo("https://backend.example.com");

        assertThat(backendConfig.getPrivateKey())
                .as("Private key should remove 0x prefix")
                .isEqualTo("123456789abcdef");

        assertThat(backendConfig.getTrustedIssuerListUri())
                .as("Trusted Issuer List URL should match")
                .isEqualTo("https://trust.example.com/issuers");

        assertThat(backendConfig.getClientsRepositoryUri())
                .as("Clients Repository URI should match")
                .isEqualTo("https://trust.example.com/services");

        assertThat(backendConfig.getRevocationListUri())
                .as("Revocation List URI should match")
                .isEqualTo("https://trust.example.com/revoked");
    }

    @EnableConfigurationProperties(BackendProperties.class)
    static class TestConfig {
    }
}
