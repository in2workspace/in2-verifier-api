package es.in2.verifier.infrastructure.config.properties;

public class ConfigurationProperties {

    // Default values
    public static final String DEFAULT_TENANT = "265fcba2-1a60-40ed-8565-16d9dc0f41f3";

    // Security Configurations
    public static final String PRIVATE_KEY = "private_key";
    public static final String AUTHORIZATION_SERVER_URL = "authorization_server_url";
    public static final String QR_CODE_EXPIRATION_TIME_IN_MINUTES = "qr_code_expiration_time_minutes";
    public static final String ACCESS_TOKEN_EXPIRATION_TIME_IN_MINUTES = "access_token_expiration_time_minutes";

    // DOME Trust Framework URI
    public static final String DOME_TRUSTED_ISSUERS_LIST_URI = "dome_trusted_issuers_list_uri";
    public static final String DOME_TRUSTED_SERVICES_LIST_URI = "dome_trusted_services_list_uri";
    public static final String DOME_REVOKED_CREDENTIALS_LIST_URI = "dome_revoked_credentials_list_uri";

    // User Interface URLs
    public static final String LOGIN_PAGE_ONBOARDING_GUIDE_URL = "login_page_onboarding_guide_url";
    public static final String LOGIN_PAGE_USER_SUPPORT_URL = "login_page_user_support_url";
    public static final String LOGIN_PAGE_WALLET_URL = "login_page_wallet_url";

    ConfigurationProperties() {
        throw new IllegalStateException("Utility class");
    }

}
