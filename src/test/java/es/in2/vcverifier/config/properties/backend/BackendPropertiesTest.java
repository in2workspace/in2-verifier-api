package es.in2.vcverifier.config.properties.backend;

import es.in2.vcverifier.config.properties.BackendProperties;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(classes = BackendPropertiesTest.TestConfig.class)
@ActiveProfiles("test")
@TestPropertySource(properties = {
        "verifier.backend.url=https://backend.example.com",
        "verifier.backend.identity.privateKey=some-private-key",
        "verifier.backend.trustFrameworks[0].trustedIssuersListUrl.uri=https://trust.example.com/issuers",
        "verifier.backend.trustFrameworks[0].trustedServicesListUrl.uri=https://trust.example.com/services",
        "verifier.backend.trustFrameworks[0].revokedCredentialListUrl.uri=https://trust.example.com/revoked"
})
class BackendPropertiesTest {

    @Autowired
    private BackendProperties backendProperties;

    @Test
    void testBackendProperties() {
        BackendProperties.Identity expectedIdentity = new BackendProperties.Identity("some-private-key");

        BackendProperties.TrustFramework expectedTrustFramework = new BackendProperties.TrustFramework(
                new BackendProperties.TrustedIssuersListUrl("https://trust.example.com/issuers"),
                new BackendProperties.TrustedServicesListUrl("https://trust.example.com/services"),
                new BackendProperties.RevokedCredentialListUrl("https://trust.example.com/revoked")
        );

        assertThat(backendProperties.url())
                .as("Backend URL should match")
                .isEqualTo("https://backend.example.com");

        assertThat(backendProperties.identity())
                .as("Identity should match the provided private key")
                .isEqualTo(expectedIdentity);

        assertThat(backendProperties.trustFrameworks())
                .as("Trust frameworks should contain the expected data")
                .isEqualTo(List.of(expectedTrustFramework));

        assertThat(backendProperties.getFirstTrustFramework())
                .as("getFirstTrustFramework should return the first framework or a default instance")
                .isEqualTo(expectedTrustFramework);
    }

    @EnableConfigurationProperties(BackendProperties.class)
    static class TestConfig {
    }
}
