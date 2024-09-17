package es.in2.vcverifier.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.ConstructorBinding;

@ConfigurationProperties(prefix = "spring.security.oauth2")
public record SecurityProperties(String authorizationServer) {

    @ConstructorBinding
    public SecurityProperties {
    }
}
