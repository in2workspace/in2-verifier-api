package es.in2.vcverifier.service;

import es.in2.vcverifier.model.ExternalTrustedListYamlData;
import es.in2.vcverifier.model.issuer.IssuerCredentialsCapabilities;

import java.util.List;

public interface TrustFrameworkService {
    List<IssuerCredentialsCapabilities> getTrustedIssuerListData(String id);
    List<String> getRevokedCredentialIds();
    ExternalTrustedListYamlData fetchAllowedClient();
}
