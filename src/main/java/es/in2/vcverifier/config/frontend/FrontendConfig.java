package es.in2.vcverifier.config.frontend;

public interface FrontendConfig {

    // URLS GETTERS
    String getOnboardingUrl();
    String getSupportUrl();
    String getWalletUrl();

    // COLORS GETTERS
    String getPrimaryColor();
    String getPrimaryContrastColor();
    String getSecondaryColor();
    String getSecondaryContrastColor();

    // LOGOS GETTERS
    String getLogoSrc();
    String getFaviconSrc();
}
