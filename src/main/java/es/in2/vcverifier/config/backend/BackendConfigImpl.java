package es.in2.vcverifier.config.backend;

import es.in2.vcverifier.config.properties.BackendProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@Configuration
@EnableConfigurationProperties(BackendProperties.class)
public class BackendConfigImpl implements BackendConfig {

    private final BackendProperties properties;

    public BackendConfigImpl(BackendProperties properties) {
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
        return properties.getFirstTrustFramework().trustedIssuersListUrl().uri();
    }

    public String getClientsRepositoryUri() {
        return properties.getFirstTrustFramework().trustedServicesListUrl().uri();
    }

    public String getRevocationListUri() {
        return properties.getFirstTrustFramework().revokedCredentialListUrl().uri();
    }
}
