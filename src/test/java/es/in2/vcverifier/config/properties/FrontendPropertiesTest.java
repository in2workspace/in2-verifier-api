package es.in2.vcverifier.config.properties;

import es.in2.vcverifier.config.properties.frontend.FrontendProperties;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(classes = FrontendPropertiesTest.TestConfig.class)
@TestPropertySource(properties = {
        "verifier.frontend.urls.onboarding=https://example.com/onboarding",
        "verifier.frontend.urls.support=https://example.com/support",
        "verifier.frontend.urls.wallet=https://example.com/wallet",
        "verifier.frontend.logoSrc=logo.png",
        "verifier.frontend.faviconSrc=favicon.ico",
        "verifier.frontend.colors.primary=#FF0000",
        "verifier.frontend.colors.primaryContrast=#FFFFFF",
        "verifier.frontend.colors.secondary=#00ADD3",
        "verifier.frontend.colors.secondaryContrast=#000000"
})
class FrontendPropertiesTest {

    @Autowired
    private FrontendProperties frontendProperties;

    @Test
    void testFrontendProperties() {
        FrontendProperties.Urls expectedUrls = new FrontendProperties.Urls(
                "https://example.com/onboarding",
                "https://example.com/support",
                "https://example.com/wallet"
        );

        FrontendProperties.Colors expectedColors = new FrontendProperties.Colors(
                "#FF0000",
                "#FFFFFF",
                "#00ADD3",
                "#000000"
        );

        assertThat(frontendProperties.urls())
                .as("URLs should match the provided values")
                .isEqualTo(expectedUrls);

        assertThat(frontendProperties.colors())
                .as("Colors should match the provided values")
                .isEqualTo(expectedColors);

        assertThat(frontendProperties.logoSrc())
                .as("Logo source should be 'logo.png'")
                .isEqualTo("logo.png");

        assertThat(frontendProperties.faviconSrc())
                .as("Favicon source should be 'favicon.ico'")
                .isEqualTo("favicon.ico");
    }

    @EnableConfigurationProperties(FrontendProperties.class)
    static class TestConfig {
    }
}
