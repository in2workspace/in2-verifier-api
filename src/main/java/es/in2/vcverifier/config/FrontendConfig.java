package es.in2.vcverifier.config;

import es.in2.vcverifier.config.properties.FrontendProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
public class FrontendConfig {

    private final FrontendProperties properties;

    public String getOnboardingUrl() {
        return properties.urls().onboarding();
    }

    public String getSupportUrl() {
        return properties.urls().support();
    }

    public String getWalletUrl() {
        return properties.urls().wallet();
    }

    public String getPrimaryColor() {
        return properties.colors().primary();
    }

    public String getPrimaryContrastColor() {
        return properties.colors().primaryContrast();
    }

    public String getSecondaryColor() {
        return properties.colors().secondary();
    }

    public String getSecondaryContrastColor() {
        return properties.colors().secondaryContrast();
    }

    public String getLogoSrc() {
        return properties.logoSrc();
    }

    public String getFaviconSrc() {
        return properties.faviconSrc();
    }
}
