package es.in2.vcverifier.service;

import es.in2.vcverifier.model.issuer.IssuerCredentialsCapabilities;

public interface TrustedIssuerListService {
    IssuerCredentialsCapabilities getTrustedIssuerListData(String id);
}
