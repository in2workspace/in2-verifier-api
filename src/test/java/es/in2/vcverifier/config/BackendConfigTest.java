package es.in2.vcverifier.config;

import es.in2.vcverifier.config.BackendConfig;
import es.in2.vcverifier.config.properties.BackendProperties;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.ConfigDataApplicationContextInitializer;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ContextConfiguration;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(classes = {BackendConfig.class, BackendConfigTest.TestConfig.class})
@ActiveProfiles("test")
@ContextConfiguration(initializers = ConfigDataApplicationContextInitializer.class)
class BackendConfigTest {

    @Autowired
    private BackendConfig backendConfig;

    @Test
    void testBackendConfig() {
        assertThat(backendConfig.getUrl())
                .as("Backend URL should match")
                .isEqualTo("https://backend.example.com");

    // todo   assertThat(backendConfig.getPrivateKey())
    //                .as("Private key should remove 0x prefix")
    //                .isEqualTo("123456789abcdef");

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

    @Configuration
    @EnableConfigurationProperties(BackendProperties.class)
    static class TestConfig {
    }
}
