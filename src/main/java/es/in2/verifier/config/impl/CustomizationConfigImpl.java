package es.in2.verifier.config.impl;

import es.in2.verifier.config.CustomizationConfig;
import es.in2.verifier.config.properties.CustomizationsProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
public class CustomizationConfigImpl implements CustomizationConfig {

    private final CustomizationsProperties customizationsProperties;

    @Override
    public String getPrimaryColor() {
        return customizationsProperties.colors().primary();
    }

    @Override
    public String getPrimaryContrastColor() {
        return customizationsProperties.colors().primaryContrast();
    }

    @Override
    public String getSecondaryColor() {
        return customizationsProperties.colors().secondary();
    }

    @Override
    public String getSecondaryContrastColor() {
        return customizationsProperties.colors().secondaryContrast();
    }

    @Override
    public String getLogoSrc() {
        return customizationsProperties.logoSrc();
    }

    @Override
    public String getFaviconSrc() {
        return customizationsProperties.faviconSrc();
    }

}
