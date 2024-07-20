package es.in2.verifier.service.impl;

import es.in2.verifier.config.ApplicationConfig;
import es.in2.verifier.service.AuthorizationRequestService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
@RequiredArgsConstructor
public class AuthorizationRequestServiceImpl implements AuthorizationRequestService {

    private static final String RESPONSE_TYPE = "vp_token";
    private static final String RESPONSE_MODE = "direct_post";
    private final ApplicationConfig applicationConfig;

    @Override
    public Mono<String> generateAuthorizationRequest() {
        String authorizationRequestTemplate = "openid://?" +
                "response_type=%s" +
                "&response_mode=%s" +
                "&client_id=%s" +
                "&redirect_uri=%s";
        String redirectUriTemplate = "%s%s&state=%s&nonce=%s&scope=%s";
        String clientId = applicationConfig.getClientId();
        final String redirectUri = String.format(redirectUriTemplate,
                applicationConfig.getExternalDomain(),
                applicationConfig.getAuthorizationResponsePath(),
                "state", // todo: generate random state and persist it in memory
                "nonce", // todo: generate random nonce and persist it in memory
                "didRead,defaultScope"); // todo: scope is requested to Credential Config Service
        return Mono.just(String.format(authorizationRequestTemplate,
                RESPONSE_TYPE,
                RESPONSE_MODE,
                clientId,
                redirectUri));
    }

}
