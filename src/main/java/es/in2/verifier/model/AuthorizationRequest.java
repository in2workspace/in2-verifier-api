package es.in2.verifier.model;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;

import java.util.Optional;

@Builder
@Schema(description = "Authorization Request following the definition given in RFC6749 and recommendations in I-D.ietf-oauth-security-topics.")
public record AuthorizationRequest(
        @Schema(description = "Response type",
                example = "vp_token",
                requiredMode = Schema.RequiredMode.REQUIRED)
        String responseType,

        @Schema(description = "Client ID",
                example = "https://client.example.org/cb",
                requiredMode = Schema.RequiredMode.REQUIRED)
        String clientId,

        @Schema(description = "Redirect URI",
                example = "https://client.example.org/cb",
                requiredMode = Schema.RequiredMode.REQUIRED)
        String redirectUri,

        @Schema(description = "Presentation Definition JSON object",
                example = "{...}",
                requiredMode = Schema.RequiredMode.REQUIRED)
        String presentationDefinition,

        @Schema(description = "URI pointing to a resource where a Presentation Definition JSON object can be retrieved",
                example = "https://example.org/presentation-definition",
                requiredMode = Schema.RequiredMode.REQUIRED)
        String presentationDefinitionUri,

        @Schema(description = "Client ID Scheme",
                example = "x509_san_dns",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED)
        Optional<String> clientIdScheme,

        @Schema(description = "Verifier metadata values as a JSON object",
                example = "{...}",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED)
        Optional<String> clientMetadata,

        @Schema(description = "Request URI",
                example = "https://client.example.org/request/vapof4ql2i7m41m68uep",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED)
        Optional<String> requestUri,

        @Schema(description = "HTTP method to be used when the request_uri parameter is included",
                example = "post",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED)
        Optional<String> requestUriMethod,

        @Schema(description = "Nonce value",
                example = "n-0S6_WzA2Mj",
                requiredMode = Schema.RequiredMode.REQUIRED)
        String nonce,

        @Schema(description = "Scope value",
                example = "openid",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED)
        Optional<String> scope,

        @Schema(description = "Response mode",
                example = "fragment",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED)
        Optional<String> responseMode

) {
}

