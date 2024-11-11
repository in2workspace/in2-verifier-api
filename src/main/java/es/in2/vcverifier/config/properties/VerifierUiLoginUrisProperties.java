package es.in2.vcverifier.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "verifier.ui.login.uris")
public record VerifierUiLoginUrisProperties(String onboardingUri, String supportUri, String walletUri) {
}
