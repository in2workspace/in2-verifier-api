package es.in2.vcverifier.config.backend;

public interface BackendConfig {

    String getUrl();

    String getPrivateKey();

    String getTrustedIssuerListUri();

    String getClientsRepositoryUri();

    String getRevocationListUri();
}
