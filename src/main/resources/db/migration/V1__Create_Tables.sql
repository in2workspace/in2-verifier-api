CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE SCHEMA IF NOT EXISTS verifier;

CREATE TABLE IF NOT EXISTS verifier.tenant_configurations
(
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id    VARCHAR(255) NOT NULL,
    configuration_key   VARCHAR(255) NOT NULL,
    configuration_value TEXT,
    UNIQUE (tenant_id, configuration_key)
);
