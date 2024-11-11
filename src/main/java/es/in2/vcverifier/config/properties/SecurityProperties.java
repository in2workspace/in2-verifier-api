package es.in2.vcverifier.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.boot.context.properties.bind.ConstructorBinding;

import java.util.Optional;

@ConfigurationProperties(prefix = "security")
public record SecurityProperties(String authorizationServer, @NestedConfigurationProperty TokenProperties token,
                                 @NestedConfigurationProperty LoginCodeProperties loginCode) {

    @ConstructorBinding
    public SecurityProperties(String authorizationServer, TokenProperties token, LoginCodeProperties loginCode) {
        this.authorizationServer = authorizationServer;
        this.token = Optional.ofNullable(token).orElse(new TokenProperties(null));
        this.loginCode = Optional.ofNullable(loginCode).orElse(new LoginCodeProperties(null));
    }

    public record TokenProperties(@NestedConfigurationProperty AccessTokenProperties accessToken) {

        @ConstructorBinding
        public TokenProperties(AccessTokenProperties accessToken) {
            this.accessToken = Optional.ofNullable(accessToken).orElse(new AccessTokenProperties("30", "MINUTES"));
        }

        public record AccessTokenProperties(String expiration, String cronUnit) {
        }
    }

    public record LoginCodeProperties(@NestedConfigurationProperty ExpirationProperties expirationProperties) {

        @ConstructorBinding
        public LoginCodeProperties(ExpirationProperties expirationProperties) {
            this.expirationProperties = Optional.ofNullable(expirationProperties).orElse(new ExpirationProperties("5", "MINUTES"));
        }

        public record ExpirationProperties(String expiration, String cronUnit) {
        }
    }
}

