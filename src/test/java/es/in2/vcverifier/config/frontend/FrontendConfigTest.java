package es.in2.vcverifier.config.frontend;

import es.in2.vcverifier.config.FrontendConfig;
import es.in2.vcverifier.config.properties.FrontendProperties;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.ConfigDataApplicationContextInitializer;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(classes = {FrontendConfig.class, FrontendConfigImplTest.TestConfig.class})
@ActiveProfiles("test")
@ContextConfiguration(initializers = ConfigDataApplicationContextInitializer.class)
class FrontendConfigImplTest {

    @Autowired
    private FrontendConfig frontendConfig;

    @Test
    void testFrontendConfig() {
        assertThat(frontendConfig.getOnboardingUrl())
                .as("Onboarding URL should match")
                .isEqualTo("https://example.com/onboarding");

        assertThat(frontendConfig.getSupportUrl())
                .as("Support URL should match")
                .isEqualTo("https://example.com/support");

        assertThat(frontendConfig.getWalletUrl())
                .as("Wallet URL should match")
                .isEqualTo("https://example.com/wallet");

        assertThat(frontendConfig.getPrimaryColor())
                .as("Primary color should match")
                .isEqualTo("#FF0000");

        assertThat(frontendConfig.getPrimaryContrastColor())
                .as("Primary contrast color should match")
                .isEqualTo("#FFFFFF");

        assertThat(frontendConfig.getSecondaryColor())
                .as("Secondary color should match")
                .isEqualTo("#00ADD3");

        assertThat(frontendConfig.getSecondaryContrastColor())
                .as("Secondary contrast color should match")
                .isEqualTo("#000000");

        assertThat(frontendConfig.getLogoSrc())
                .as("Logo source should match")
                .isEqualTo("logo.png");

        assertThat(frontendConfig.getFaviconSrc())
                .as("Favicon source should match")
                .isEqualTo("favicon.ico");
    }

    @EnableConfigurationProperties(FrontendProperties.class)
    static class TestConfig {
    }
}
