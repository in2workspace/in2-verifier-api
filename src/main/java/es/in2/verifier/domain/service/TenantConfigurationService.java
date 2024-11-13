package es.in2.verifier.domain.service;

public interface TenantConfigurationService {
    String getConfigurationByTenantAndKey(String tenantId, String key);
}
