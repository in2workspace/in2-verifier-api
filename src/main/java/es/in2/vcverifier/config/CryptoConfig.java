package es.in2.vcverifier.config;

import es.in2.vcverifier.config.properties.CryptoProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
public class CryptoConfig {

    private final CryptoProperties cryptoProperties;

    public String getPrivateKey() {
        String privateKey = cryptoProperties.privateKey();
        if (privateKey.startsWith("0x")) {
            privateKey = privateKey.substring(2);
        }
        return privateKey;
    }

}
