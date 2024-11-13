package es.in2.verifier.domain.service.impl;

import es.in2.verifier.domain.exception.ConfigurationRetrievalException;
import es.in2.verifier.domain.model.entity.TenantConfiguration;
import es.in2.verifier.domain.service.TenantConfigurationService;
import es.in2.verifier.infrastructure.repository.TenantConfigurationRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class TenantConfigurationServiceImpl implements TenantConfigurationService {

    private final TenantConfigurationRepository tenantConfigurationRepository;

    @Override
    public String getConfigurationByTenantAndKey(String tenantId, String configurationKey) {
        return tenantConfigurationRepository
                .findByTenantIdAndConfigurationKey(tenantId, configurationKey)
                .map(TenantConfiguration::getConfigurationValue)
                .orElseThrow(() -> new ConfigurationRetrievalException("Configuration not found"));
    }

}
