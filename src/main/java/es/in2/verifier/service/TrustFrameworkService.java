package es.in2.verifier.service;

import es.in2.verifier.model.ExternalTrustedListYamlData;
import es.in2.verifier.model.issuer.IssuerCredentialsCapabilities;

import java.util.List;

public interface TrustFrameworkService {
    List<IssuerCredentialsCapabilities> getTrustedIssuerListData(String id);
    List<String> getRevokedCredentialIds();
    ExternalTrustedListYamlData fetchAllowedClient();
}
