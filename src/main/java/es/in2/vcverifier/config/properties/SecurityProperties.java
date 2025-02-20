package es.in2.vcverifier.config.properties;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.boot.context.properties.bind.ConstructorBinding;
import org.springframework.validation.annotation.Validated;

import java.util.Optional;

import static es.in2.vcverifier.util.Constants.MINUTES;
@Validated
@ConfigurationProperties(prefix = "security")
public record SecurityProperties(
        @NotNull @NestedConfigurationProperty TokenProperties token) {

    public record TokenProperties(@NestedConfigurationProperty AccessTokenProperties accessToken,
                                  @NestedConfigurationProperty IdTokenProperties idToken) {

        @ConstructorBinding
        public TokenProperties(AccessTokenProperties accessToken, IdTokenProperties idToken) {
            this.accessToken = Optional.ofNullable(accessToken)
                    .orElse(new AccessTokenProperties("30", MINUTES));
            this.idToken = Optional.ofNullable(idToken)
                    .orElse(new IdTokenProperties("2", MINUTES));
        }

        public record AccessTokenProperties(String expiration, String cronUnit) {

            @ConstructorBinding
            public AccessTokenProperties(String expiration, String cronUnit) {
                this.expiration = (expiration == null || expiration.isBlank()) ? "30" : expiration;
                this.cronUnit = (cronUnit == null || cronUnit.isBlank()) ? MINUTES : cronUnit;
            }
        }

        public record IdTokenProperties(String expiration, String cronUnit) {

            @ConstructorBinding
            public IdTokenProperties(String expiration, String cronUnit) {
                this.expiration = (expiration == null || expiration.isBlank()) ? "2" : expiration;
                this.cronUnit = (cronUnit == null || cronUnit.isBlank()) ? MINUTES : cronUnit;
            }
        }
    }
}


