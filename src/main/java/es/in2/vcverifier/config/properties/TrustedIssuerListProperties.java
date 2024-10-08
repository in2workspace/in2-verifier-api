package es.in2.vcverifier.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "trusted-issuer-list")
public record TrustedIssuerListProperties (
        String uri

){
}
