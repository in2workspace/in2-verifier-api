package es.in2.vcverifier.service;

import es.in2.vcverifier.model.issuer.IssuerCredentialsCapabilities;

import java.util.List;

public interface TrustedIssuerListService {
    List<IssuerCredentialsCapabilities> getTrustedIssuerListData(String id);
}
