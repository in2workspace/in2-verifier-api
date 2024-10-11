package es.in2.vcverifier.config.properties;

import es.in2.vcverifier.objectmothers.UiUrlsPropertiesMother;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
class UiUrlPropertiesTest {
    @Autowired
    private UiUrlsProperties uiUrlsProperties;

    private static final String ONBOARDING_URL = UiUrlsPropertiesMother.createOnboardingUrl();
    private static final String SUPPORT_URL = UiUrlsPropertiesMother.createSupportUrl();
    private static final String WALLET_URL = UiUrlsPropertiesMother.createWalletUrl();

    @DynamicPropertySource
    static void setDynamicProperties(DynamicPropertyRegistry registry) {
        registry.add("ui.urls.onboardingUrl", () -> ONBOARDING_URL);
        registry.add("ui.urls.supportUrl", () -> SUPPORT_URL);
        registry.add("ui.urls.walletUrl", () -> WALLET_URL);
    }

    @Test
    void testUiUrlsOnboardingUrl() {
        assertThat(uiUrlsProperties.onboardingUrl()).isEqualTo(ONBOARDING_URL);
    }

    @Test
    void testUiUrlSupportUrl() {
        assertThat(uiUrlsProperties.supportUrl()).isEqualTo(SUPPORT_URL);
    }

    @Test
    void testUiUrlwalletUrl() {
        assertThat(uiUrlsProperties.walletUrl()).isEqualTo(WALLET_URL);
    }
}