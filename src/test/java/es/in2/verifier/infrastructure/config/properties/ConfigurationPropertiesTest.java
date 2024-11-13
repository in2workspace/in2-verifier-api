package es.in2.verifier.infrastructure.config.properties;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(MockitoExtension.class)
class ConfigurationPropertiesTest {

    @Test
    void defaultTenantIsCorrect() {
        assertEquals("265fcba2-1a60-40ed-8565-16d9dc0f41f3", ConfigurationProperties.DEFAULT_TENANT);
    }

    @Test
    void privateKeyIsCorrect() {
        assertEquals("private_key", ConfigurationProperties.PRIVATE_KEY);
    }

    @Test
    void authorizationServerUrlIsCorrect() {
        assertEquals("authorization_server_url", ConfigurationProperties.AUTHORIZATION_SERVER_URL);
    }

    @Test
    void qrCodeExpirationTimeInMinutesIsCorrect() {
        assertEquals("qr_code_expiration_time_minutes", ConfigurationProperties.QR_CODE_EXPIRATION_TIME_IN_MINUTES);
    }

    @Test
    void accessTokenExpirationTimeInMinutesIsCorrect() {
        assertEquals("access_token_expiration_time_minutes", ConfigurationProperties.ACCESS_TOKEN_EXPIRATION_TIME_IN_MINUTES);
    }

    @Test
    void domeTrustedIssuersListUriIsCorrect() {
        assertEquals("dome_trusted_issuers_list_uri", ConfigurationProperties.DOME_TRUSTED_ISSUERS_LIST_URI);
    }

    @Test
    void domeTrustedServicesListUriIsCorrect() {
        assertEquals("dome_trusted_services_list_uri", ConfigurationProperties.DOME_TRUSTED_SERVICES_LIST_URI);
    }

    @Test
    void domeRevokedCredentialsListUriIsCorrect() {
        assertEquals("dome_revoked_credentials_list_uri", ConfigurationProperties.DOME_REVOKED_CREDENTIALS_LIST_URI);
    }

    @Test
    void loginPageOnboardingGuideUrlIsCorrect() {
        assertEquals("login_page_onboarding_guide_url", ConfigurationProperties.LOGIN_PAGE_ONBOARDING_GUIDE_URL);
    }

    @Test
    void loginPageUserSupportUrlIsCorrect() {
        assertEquals("login_page_user_support_url", ConfigurationProperties.LOGIN_PAGE_USER_SUPPORT_URL);
    }

    @Test
    void loginPageWalletUrlIsCorrect() {
        assertEquals("login_page_wallet_url", ConfigurationProperties.LOGIN_PAGE_WALLET_URL);
    }

    @Test
    void utilityClassConstructorThrowsException() {
        assertThrows(IllegalStateException.class, ConfigurationProperties::new);
    }

}
