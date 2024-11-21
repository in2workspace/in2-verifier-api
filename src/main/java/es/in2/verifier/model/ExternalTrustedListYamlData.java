package es.in2.verifier.model;

import lombok.Builder;

import java.util.List;

@Builder
public record ExternalTrustedListYamlData(
        List<ClientData> clients
) {}
