package es.in2.vcverifier.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "ui.urls")
public record UiUrlsProperties(String onboardingUrl, String supportUrl, String walletUrl) {
}
