package es.in2.verifier.config.impl;

import es.in2.verifier.config.properties.CustomizationsProperties;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CustomizationConfigImplTest {

    @Test
    void testCustomizationConfigImpl() {
        CustomizationsProperties.Colors colors = new CustomizationsProperties.Colors(
                "#14274A",
                "#ffffff",
                "#00ADD3",
                "#000000"
        );

        String logoSrc = "logo.png";
        String faviconSrc = "favicon.ico";
        CustomizationsProperties customizationsProperties = new CustomizationsProperties(colors, logoSrc, faviconSrc);

        CustomizationConfigImpl customizationConfig = new CustomizationConfigImpl(customizationsProperties);

        assertEquals("#14274A", customizationConfig.getPrimaryColor());
        assertEquals("#ffffff", customizationConfig.getPrimaryContrastColor());
        assertEquals("#00ADD3", customizationConfig.getSecondaryColor());
        assertEquals("#000000", customizationConfig.getSecondaryContrastColor());
        assertEquals("logo.png", customizationConfig.getLogoSrc());
        assertEquals("favicon.ico", customizationConfig.getFaviconSrc());
    }
}
