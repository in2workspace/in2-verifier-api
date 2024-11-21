package es.in2.verifier.config;

import es.in2.verifier.config.properties.CryptoProperties;
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
