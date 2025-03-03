package es.in2.vcverifier.config.properties;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.test.context.ActiveProfiles;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(classes = BackendPropertiesTest.TestConfig.class)
@ActiveProfiles("test")
class BackendPropertiesTest {

    @Autowired
    private BackendProperties backendProperties;

    @Test
    void testBackendProperties() {
        BackendProperties.Identity expectedIdentity = new BackendProperties.Identity("0x73e509a7681d4a395b1ced75681c4dc4020dbab02da868512276dd766733d5b5");

        BackendProperties.TrustFramework expectedTrustFramework = new BackendProperties.TrustFramework(
                "DOME",
                "https://raw.githubusercontent.com",
                "https://raw.githubusercontent.com/in2workspace/in2-dome-gitops/refs/heads/main/trust-framework/trusted_services_list.yaml",
                "https://raw.githubusercontent.com/in2workspace/in2-dome-gitops/refs/heads/main/trust-framework/revoked_credential_list.yaml"
        );

        assertThat(backendProperties.url())
                .as("Backend URL should match")
                .isEqualTo("https://raw.githubusercontent.com");

        assertThat(backendProperties.identity())
                .as("Identity should match the provided private key")
                .isEqualTo(expectedIdentity);

        assertThat(backendProperties.trustFrameworks())
                .as("Trust frameworks should contain the expected data")
                .isEqualTo(List.of(expectedTrustFramework));

        assertThat(backendProperties.getDOMETrustFrameworkByName())
                .as("getDOMETrustFrameworkByName should return the expected DOME framework")
                .isEqualTo(expectedTrustFramework);
    }

    @Test
    void testMissingMandatoryUrlCausesError() {
        new ApplicationContextRunner()
                .withUserConfiguration(TestConfig.class)
                .withPropertyValues(
                        // Omit url:
                        // "verifier.backend.url=https://raw.githubusercontent.com",
                        "verifier.backend.identity.privateKey=test-private-key",
                        "verifier.backend.trustFrameworks[0].name=DOME",
                        "verifier.backend.trustFrameworks[0].trustedIssuersListUrl=https://raw.githubusercontent.com",
                        "verifier.backend.trustFrameworks[0].trustedServicesListUrl=https://raw.githubusercontent.com/in2workspace/in2-dome-gitops/refs/heads/main/trust-framework/trusted_services_list.yaml",
                        "verifier.backend.trustFrameworks[0].revokedCredentialListUrl=https://raw.githubusercontent.com/in2workspace/in2-dome-gitops/refs/heads/main/trust-framework/revoked_credential_list.yaml"
                )
                .run(context -> {
                    assertThat(context).hasFailed();
                });
    }

    @Test
    void testMissingMandatoryPrivateKeyCausesError() {
        new ApplicationContextRunner()
                .withUserConfiguration(TestConfig.class)
                .withPropertyValues(
                        "verifier.backend.url=https://raw.githubusercontent.com",
                        // Omit privateKey:
                        // "verifier.backend.identity.privateKey" no s'estableix
                        "verifier.backend.trustFrameworks[0].name=DOME",
                        "verifier.backend.trustFrameworks[0].trustedIssuersListUrl=https://raw.githubusercontent.com",
                        "verifier.backend.trustFrameworks[0].trustedServicesListUrl=https://raw.githubusercontent.com/in2workspace/in2-dome-gitops/refs/heads/main/trust-framework/trusted_services_list.yaml",
                        "verifier.backend.trustFrameworks[0].revokedCredentialListUrl=https://raw.githubusercontent.com/in2workspace/in2-dome-gitops/refs/heads/main/trust-framework/revoked_credential_list.yaml"
                )
                .run(context -> {
                    assertThat(context).hasFailed();
                });
    }

    @Test
    void testIncludingAllMandatoryProperties() {
        new ApplicationContextRunner()
                .withUserConfiguration(TestConfig.class)
                .withPropertyValues(
                        "verifier.backend.url=https://raw.githubusercontent.com",
                        "verifier.backend.identity.privateKey=test-private-key",
                        "verifier.backend.trustFrameworks[0].name=DOME",
                        "verifier.backend.trustFrameworks[0].trustedIssuersListUrl=https://raw.githubusercontent.com",
                        "verifier.backend.trustFrameworks[0].trustedServicesListUrl=https://raw.githubusercontent.com/in2workspace/in2-dome-gitops/refs/heads/main/trust-framework/trusted_services_list.yaml",
                        "verifier.backend.trustFrameworks[0].revokedCredentialListUrl=https://raw.githubusercontent.com/in2workspace/in2-dome-gitops/refs/heads/main/trust-framework/revoked_credential_list.yaml"
                )
                .run(context -> {
                    assertThat(context).hasNotFailed();
                });
    }

    @EnableConfigurationProperties(BackendProperties.class)
    static class TestConfig {
    }
}
