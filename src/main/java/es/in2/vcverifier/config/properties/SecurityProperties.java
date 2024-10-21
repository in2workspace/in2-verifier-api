package es.in2.vcverifier.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.boot.context.properties.bind.ConstructorBinding;

import java.util.Optional;

@ConfigurationProperties(prefix = "security")
public record SecurityProperties(String authorizationServer, @NestedConfigurationProperty TokenProperties token) {

    @ConstructorBinding
    public SecurityProperties(String authorizationServer, TokenProperties token) {
        this.authorizationServer = authorizationServer;
        this.token = Optional.ofNullable(token).orElse(new TokenProperties(null));
    }

    public record TokenProperties(@NestedConfigurationProperty AccessTokenProperties accessToken) {

        @ConstructorBinding
        public TokenProperties(AccessTokenProperties accessToken) {
            this.accessToken = Optional.ofNullable(accessToken).orElse(new AccessTokenProperties(null, null));
        }

        public record AccessTokenProperties(String expiration, String cronUnit) {
        }

    }

}
