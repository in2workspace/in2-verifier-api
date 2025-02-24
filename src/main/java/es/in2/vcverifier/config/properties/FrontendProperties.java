package es.in2.vcverifier.config.properties;

import jakarta.validation.constraints.NotNull;
import org.hibernate.validator.constraints.URL;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "verifier.frontend")
public record FrontendProperties(
        @NotNull @NestedConfigurationProperty Urls urls,
        @NestedConfigurationProperty Colors colors,
        @NotNull String logoSrc,
        String faviconSrc) {

    public record Urls(
            @NotNull @URL String onboarding,
            @NotNull @URL String support,
            @NotNull @URL String wallet) {}

    public record Colors(
            String primary,
            String primaryContrast,
            String secondary,
            String secondaryContrast
    ) {}
}
