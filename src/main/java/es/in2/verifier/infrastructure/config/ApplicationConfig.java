package es.in2.verifier.infrastructure.config;

import es.in2.verifier.domain.service.TenantConfigurationService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;

import static es.in2.verifier.infrastructure.config.properties.ConfigurationProperties.*;

@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {

    private final TenantConfigurationService tenantConfigurationService;

    public String getPrivateKey() {
        String privateKey = tenantConfigurationService.getConfigurationByTenantAndKey(DEFAULT_TENANT, PRIVATE_KEY);
        return privateKey.startsWith("0x") ? privateKey.substring(2) : privateKey;
    }

    public String getAuthorizationServerUrl() {
        return tenantConfigurationService.getConfigurationByTenantAndKey(DEFAULT_TENANT, AUTHORIZATION_SERVER_URL);
    }

    public Long getAccessTokenExpiration() {
        return Long.valueOf(tenantConfigurationService.getConfigurationByTenantAndKey(DEFAULT_TENANT,
                ACCESS_TOKEN_EXPIRATION_TIME_IN_MINUTES));
    }

    public Long getQRCodeExpiration() {
        return Long.valueOf(tenantConfigurationService.getConfigurationByTenantAndKey(DEFAULT_TENANT,
                QR_CODE_EXPIRATION_TIME_IN_MINUTES));
    }

    public String getDomeTrustedIssuersListUri() {
        return tenantConfigurationService.getConfigurationByTenantAndKey(DEFAULT_TENANT, DOME_TRUSTED_ISSUERS_LIST_URI);
    }

    public String getDomeTrustedServicesListUri() {
        return tenantConfigurationService.getConfigurationByTenantAndKey(DEFAULT_TENANT, DOME_TRUSTED_SERVICES_LIST_URI);
    }

    public String getDomeRevokedCredentialsListUri() {
        return tenantConfigurationService.getConfigurationByTenantAndKey(DEFAULT_TENANT, DOME_REVOKED_CREDENTIALS_LIST_URI);
    }

    public String getLoginPageOnboardingGuideUrl() {
        return tenantConfigurationService.getConfigurationByTenantAndKey(DEFAULT_TENANT, LOGIN_PAGE_ONBOARDING_GUIDE_URL);
    }

    public String getLoginPageUserSupportUrl() {
        return tenantConfigurationService.getConfigurationByTenantAndKey(DEFAULT_TENANT, LOGIN_PAGE_USER_SUPPORT_URL);
    }

    public String getLoginPageWalletUrl() {
        return tenantConfigurationService.getConfigurationByTenantAndKey(DEFAULT_TENANT, LOGIN_PAGE_WALLET_URL);
    }

}
