package es.in2.vcverifier.model.enums;

import es.in2.vcverifier.exception.InvalidSpringProfile;
import lombok.Getter;

@Getter
public enum Profile {
    DEFAULT("lcl"), // Currently mapped to the local environment
    LOCAL("lcl"),
    DEV("sbx"),
    TEST("dev"),
    PROD("prd");

    private final String abbreviation;

    Profile(String abbreviation) {
        this.abbreviation = abbreviation;
    }

    public static Profile fromString(String profile) {
        try {
            return Profile.valueOf(profile.toUpperCase()); // Match the string to the enum value
        } catch (IllegalArgumentException e) {
            throw new InvalidSpringProfile("Invalid profile: " + profile);
        }
    }
}
