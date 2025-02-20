package es.in2.vcverifier.config.backend;

import es.in2.vcverifier.config.properties.backend.BackendProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@Configuration
@EnableConfigurationProperties(BackendProperties.class)
public class BackendConfig {

    private final BackendProperties properties;

    public BackendConfig(BackendProperties properties) {
        this.properties = properties;
    }

    public String getUrl() {
        return properties.url();
    }

    public String getPrivateKey() {
        String privateKey = properties.identity().privateKey();
        if (privateKey.startsWith("0x")) {
            privateKey = privateKey.substring(2);
        }
        return privateKey;
    }

    public String getTrustedIssuerListUri() {
        return properties.trustFramework().trustedIssuerList().uri();
    }

    public String getClientsRepositoryUri() {
        return properties.trustFramework().clientsRepository().uri();
    }

    public String getRevocationListUri() {
        return properties.trustFramework().revocationList().uri();
    }
}

