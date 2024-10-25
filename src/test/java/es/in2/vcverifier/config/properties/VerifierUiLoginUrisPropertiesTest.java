package es.in2.vcverifier.config.properties;

import es.in2.vcverifier.objectmothers.VerifierUiLoginUrisPropertiesMother;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import static org.assertj.core.api.Assertions.assertThat;

//@SpringBootTest
//class VerifierUiLoginUrisPropertiesTest {
//    @Autowired
//    private VerifierUiLoginUrisProperties verifierUiLoginUrisProperties;
//
//    private static final String ONBOARDING_URI = VerifierUiLoginUrisPropertiesMother.createOnboardingUri();
//    private static final String SUPPORT_URI = VerifierUiLoginUrisPropertiesMother.createSupportUri();
//    private static final String WALLET_URI = VerifierUiLoginUrisPropertiesMother.createWalletUri();
//
//    @DynamicPropertySource
//    static void setDynamicProperties(DynamicPropertyRegistry registry) {
//        registry.add("verifier.ui.login.uris.onboardingUri", () -> ONBOARDING_URI);
//        registry.add("verifier.ui.login.uris.supportUri", () -> SUPPORT_URI);
//        registry.add("verifier.ui.login.uris.walletUri", () -> WALLET_URI);
//    }
//
//    @Test
//    void testUiUrlsOnboardingUrl() {
//        assertThat(verifierUiLoginUrisProperties.onboardingUri()).isEqualTo(ONBOARDING_URI);
//    }
//
//    @Test
//    void testUiUrlSupportUrl() {
//        assertThat(verifierUiLoginUrisProperties.supportUri()).isEqualTo(SUPPORT_URI);
//    }
//
//    @Test
//    void testUiUrlwalletUrl() {
//        assertThat(verifierUiLoginUrisProperties.walletUri()).isEqualTo(WALLET_URI);
//    }
//}