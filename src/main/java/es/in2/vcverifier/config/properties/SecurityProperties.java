package es.in2.vcverifier.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.boot.context.properties.bind.ConstructorBinding;

import java.util.Optional;

import static es.in2.vcverifier.util.Constants.MINUTES;

@ConfigurationProperties(prefix = "security")
public record SecurityProperties(String authorizationServer, @NestedConfigurationProperty TokenProperties token,
                                 @NestedConfigurationProperty LoginCodeProperties loginCode) {

    @ConstructorBinding
    public SecurityProperties(String authorizationServer, TokenProperties token, LoginCodeProperties loginCode) {
        this.authorizationServer = authorizationServer;
        this.token = Optional.ofNullable(token).orElse(new TokenProperties(null, null));
        this.loginCode = Optional.ofNullable(loginCode).orElse(new LoginCodeProperties(null));
    }

    public record TokenProperties(@NestedConfigurationProperty AccessTokenProperties accessToken, @NestedConfigurationProperty IdTokenProperties idToken) {

        @ConstructorBinding
        public TokenProperties(AccessTokenProperties accessToken, IdTokenProperties idToken) {
            this.accessToken = Optional.ofNullable(accessToken).orElse(new AccessTokenProperties("1", MINUTES));
            this.idToken = Optional.ofNullable(idToken).orElse(new IdTokenProperties("30", MINUTES));
        }

        public record AccessTokenProperties(String expiration, String cronUnit) {
        }
        public record IdTokenProperties(String expiration, String cronUnit) {
        }
    }

    public record LoginCodeProperties(@NestedConfigurationProperty ExpirationProperties expirationProperties) {

        @ConstructorBinding
        public LoginCodeProperties(ExpirationProperties expirationProperties) {
            this.expirationProperties = Optional.ofNullable(expirationProperties).orElse(new ExpirationProperties("5", MINUTES));
        }

        public record ExpirationProperties(String expiration, String cronUnit) {
        }
    }
}

