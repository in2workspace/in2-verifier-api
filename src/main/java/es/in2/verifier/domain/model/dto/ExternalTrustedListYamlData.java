package es.in2.verifier.domain.model.dto;

import lombok.Builder;

import java.util.List;

@Builder
public record ExternalTrustedListYamlData(
        List<ClientData> clients
) {}
