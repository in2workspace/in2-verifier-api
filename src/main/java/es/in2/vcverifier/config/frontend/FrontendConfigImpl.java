package es.in2.vcverifier.config.frontend;

import es.in2.vcverifier.config.properties.FrontendProperties;
import org.springframework.stereotype.Component;

@Component
public class FrontendConfigImpl implements FrontendConfig {

    private final FrontendProperties properties;

    public FrontendConfigImpl(FrontendProperties properties) {
        this.properties = properties;
    }

    @Override
    public String getOnboardingUrl() {
        return properties.urls().onboarding();
    }

    @Override
    public String getSupportUrl() {
        return properties.urls().support();
    }

    @Override
    public String getWalletUrl() {
        return properties.urls().wallet();
    }

    @Override
    public String getPrimaryColor() {
        return properties.colors().primary();
    }

    @Override
    public String getPrimaryContrastColor() {
        return properties.colors().primaryContrast();
    }

    @Override
    public String getSecondaryColor() {
        return properties.colors().secondary();
    }

    @Override
    public String getSecondaryContrastColor() {
        return properties.colors().secondaryContrast();
    }

    @Override
    public String getLogoSrc() {
        return properties.logoSrc();
    }

    @Override
    public String getFaviconSrc() {
        return properties.faviconSrc();
    }
}
