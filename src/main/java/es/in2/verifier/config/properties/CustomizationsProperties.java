package es.in2.verifier.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.boot.context.properties.bind.ConstructorBinding;

import java.util.Optional;

@ConfigurationProperties(prefix = "verifier.ui.customizations")
public record CustomizationsProperties(@NestedConfigurationProperty Colors colors,
                                       String logoSrc, String faviconSrc  ) {

    @ConstructorBinding
    public CustomizationsProperties(Colors colors, String logoSrc, String faviconSrc) {

        this.colors = Optional.ofNullable(colors).map(c -> new Colors(
                isEmpty(c.primary()) ? "#14274A" : c.primary(),
                isEmpty(c.primaryContrast()) ? "#ffffff" : c.primaryContrast(),
                isEmpty(c.secondary()) ? "#00ADD3" : c.secondary(),
                isEmpty(c.secondaryContrast()) ? "#000000" : c.secondaryContrast()
        )).orElse(new Colors("#14274A", "#ffffff", "#00ADD3", "#000000" ));
        this.logoSrc = logoSrc;
        this.faviconSrc = faviconSrc;
    }

    private static boolean isEmpty(String value) {
        return value == null || value.trim().isEmpty();
    }

    public record Colors(
            String primary,
            String primaryContrast,
            String secondary,
            String secondaryContrast
    ) {}

}
