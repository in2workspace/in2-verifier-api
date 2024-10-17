package es.in2.vcverifier.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "clients-repository")
public record ClientRepositoryProperties(String uri) {
}
