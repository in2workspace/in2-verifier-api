package es.in2.vcverifier.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.boot.context.properties.bind.ConstructorBinding;

import java.util.Optional;

@ConfigurationProperties(prefix = "security")
public record SecurityProperties(
        String authorizationServer,
        @NestedConfigurationProperty TokenProperties token) {

    @ConstructorBinding
    public SecurityProperties (String authorizationServer, TokenProperties token){
        this.authorizationServer = authorizationServer;
        this.token = Optional.ofNullable(token).orElse(new TokenProperties(null, null));
    }

    public record TokenProperties(
            @NestedConfigurationProperty AccessTokenProperties accessToken,
            @NestedConfigurationProperty RefreshTokenProperties refreshToken) {

        @ConstructorBinding
        public TokenProperties(AccessTokenProperties accessToken, RefreshTokenProperties refreshToken) {
            this.accessToken = Optional.ofNullable(accessToken).orElse(new AccessTokenProperties(null,null));
            this.refreshToken = Optional.ofNullable(refreshToken).orElse(new RefreshTokenProperties(null,null));
        }

        public record AccessTokenProperties(Integer expiration, String cronUnit) { }

        public record RefreshTokenProperties(Integer expiration, String cronUnit) { }

    }

}