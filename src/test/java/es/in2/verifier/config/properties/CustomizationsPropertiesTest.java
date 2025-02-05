package es.in2.verifier.config.properties;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(classes = CustomizationsPropertiesTest.TestConfig.class)
@TestPropertySource(properties = {
        "verifier.ui.customizations.logoSrc=logo.png",
        "verifier.ui.customizations.faviconSrc=favicon.ico",
        "verifier.ui.customizations.colors.primary= #FF0000",
        "verifier.ui.customizations.colors.primaryContrast=",
        "verifier.ui.customizations.colors.secondary=",
        "verifier.ui.customizations.colors.secondaryContrast=#000000"
})
public class CustomizationsPropertiesTest {

    @Autowired
    private CustomizationsProperties customizationsProperties;

    @Test
    void testCustomizationsProperties() {
        CustomizationsProperties.Colors expectedColors = new CustomizationsProperties.Colors(
                "#FF0000",
                "#ffffff",
                "#00ADD3",
                "#000000"
        );

        assertThat(customizationsProperties.colors())
                .as("The colors should combine the provided and default values")
                .isEqualTo(expectedColors);
        assertThat(customizationsProperties.logoSrc())
                .as("Logo source should be 'logo.png'")
                .isEqualTo("logo.png");
        assertThat(customizationsProperties.faviconSrc())
                .as("Favicon source should be 'favicon.ico'")
                .isEqualTo("favicon.ico");
    }

    @EnableConfigurationProperties(CustomizationsProperties.class)
    static class TestConfig {
    }
}
