package es.in2.verifier.domain.service;

import es.in2.verifier.domain.model.dto.ExternalTrustedListYamlData;
import es.in2.verifier.domain.model.dto.issuer.IssuerCredentialsCapabilities;

import java.util.List;

public interface TrustFrameworkService {
    List<IssuerCredentialsCapabilities> getTrustedIssuerListData(String id);
    List<String> getRevokedCredentialIds();
    ExternalTrustedListYamlData fetchAllowedClient();
}
