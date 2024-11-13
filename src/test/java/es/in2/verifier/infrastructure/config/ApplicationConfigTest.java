package es.in2.verifier.infrastructure.config;

import es.in2.verifier.domain.service.TenantConfigurationService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static es.in2.verifier.infrastructure.config.properties.ConfigurationProperties.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ApplicationConfigTest {

    @Mock
    private TenantConfigurationService tenantConfigurationService;

    @InjectMocks
    private ApplicationConfig applicationConfig;

    @Test
    void getPrivateKeyReturnsKeyWithoutPrefix() {
        when(tenantConfigurationService.getConfigurationByTenantAndKey(DEFAULT_TENANT, PRIVATE_KEY))
                .thenReturn("0x123456");

        String result = applicationConfig.getPrivateKey();

        assertEquals("123456", result);
    }

    @Test
    void getPrivateKeyReturnsKeyWithNoPrefix() {
        when(tenantConfigurationService.getConfigurationByTenantAndKey(DEFAULT_TENANT, PRIVATE_KEY))
                .thenReturn("123456");

        String result = applicationConfig.getPrivateKey();

        assertEquals("123456", result);
    }

    @Test
    void getAuthorizationServerUrlReturnsUrl() {
        when(tenantConfigurationService.getConfigurationByTenantAndKey(DEFAULT_TENANT, AUTHORIZATION_SERVER_URL))
                .thenReturn("http://auth.server");

        String result = applicationConfig.getAuthorizationServerUrl();

        assertEquals("http://auth.server", result);
    }

    @Test
    void getAccessTokenExpirationReturnsExpirationTime() {
        when(tenantConfigurationService.getConfigurationByTenantAndKey(DEFAULT_TENANT, ACCESS_TOKEN_EXPIRATION_TIME_IN_MINUTES))
                .thenReturn("60");

        Long result = applicationConfig.getAccessTokenExpiration();

        assertEquals(60L, result);
    }

    @Test
    void getQRCodeExpirationReturnsExpirationTime() {
        when(tenantConfigurationService.getConfigurationByTenantAndKey(DEFAULT_TENANT, QR_CODE_EXPIRATION_TIME_IN_MINUTES))
                .thenReturn("30");

        Long result = applicationConfig.getQRCodeExpiration();

        assertEquals(30L, result);
    }

    @Test
    void getDomeTrustedIssuersListUriReturnsUri() {
        when(tenantConfigurationService.getConfigurationByTenantAndKey(DEFAULT_TENANT, DOME_TRUSTED_ISSUERS_LIST_URI))
                .thenReturn("http://trusted.issuers");

        String result = applicationConfig.getDomeTrustedIssuersListUri();

        assertEquals("http://trusted.issuers", result);
    }

    @Test
    void getDomeTrustedServicesListUriReturnsUri() {
        when(tenantConfigurationService.getConfigurationByTenantAndKey(DEFAULT_TENANT, DOME_TRUSTED_SERVICES_LIST_URI))
                .thenReturn("http://trusted.services");

        String result = applicationConfig.getDomeTrustedServicesListUri();

        assertEquals("http://trusted.services", result);
    }

    @Test
    void getDomeRevokedCredentialsListUriReturnsUri() {
        when(tenantConfigurationService.getConfigurationByTenantAndKey(DEFAULT_TENANT, DOME_REVOKED_CREDENTIALS_LIST_URI))
                .thenReturn("http://revoked.credentials");

        String result = applicationConfig.getDomeRevokedCredentialsListUri();

        assertEquals("http://revoked.credentials", result);
    }

    @Test
    void getLoginPageOnboardingGuideUrlReturnsUrl() {
        when(tenantConfigurationService.getConfigurationByTenantAndKey(DEFAULT_TENANT, LOGIN_PAGE_ONBOARDING_GUIDE_URL))
                .thenReturn("http://onboarding.guide");

        String result = applicationConfig.getLoginPageOnboardingGuideUrl();

        assertEquals("http://onboarding.guide", result);
    }

    @Test
    void getLoginPageUserSupportUrlReturnsUrl() {
        when(tenantConfigurationService.getConfigurationByTenantAndKey(DEFAULT_TENANT, LOGIN_PAGE_USER_SUPPORT_URL))
                .thenReturn("http://user.support");

        String result = applicationConfig.getLoginPageUserSupportUrl();

        assertEquals("http://user.support", result);
    }

    @Test
    void getLoginPageWalletUrlReturnsUrl() {
        when(tenantConfigurationService.getConfigurationByTenantAndKey(DEFAULT_TENANT, LOGIN_PAGE_WALLET_URL))
                .thenReturn("http://wallet.url");

        String result = applicationConfig.getLoginPageWalletUrl();

        assertEquals("http://wallet.url", result);
    }

}
