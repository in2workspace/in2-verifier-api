package es.in2.vcverifier.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "trust-framework")
public record TrustFrameworkProperties(
        String issuersListUri,
        String participantsListUri,
        String clientsListUri)
{
}
