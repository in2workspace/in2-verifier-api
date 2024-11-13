package es.in2.verifier.infrastructure.repository;

import es.in2.verifier.domain.model.entity.TenantConfiguration;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface TenantConfigurationRepository extends JpaRepository<TenantConfiguration, UUID> {

    Optional<TenantConfiguration> findByTenantIdAndConfigurationKey(String tenantId, String configurationKey);

}
