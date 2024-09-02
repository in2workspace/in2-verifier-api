package es.in2.vcverifier.security.filters;

import com.nimbusds.jose.JWSObject;
import es.in2.vcverifier.exception.JWTVerificationException;
import es.in2.vcverifier.exception.RequestMismatchException;
import es.in2.vcverifier.exception.RequestObjectRetrievalException;
import es.in2.vcverifier.exception.UnauthorizedClientException;
import es.in2.vcverifier.service.DIDService;
import es.in2.vcverifier.service.DIDServiceImpl;
import es.in2.vcverifier.service.JWTService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.text.ParseException;
import java.util.List;

@Slf4j
@RequiredArgsConstructor
public class CustomAuthorizationRequestConverter implements AuthenticationConverter {

    private static final String CLIENT_ID_FILE_PATH = "resources/static/client_id_list.txt";
    private final DIDService didService;
    private final JWTService jwtService;

    /**
     * The Authorization Request MUST be signed by the Client, and MUST use the request_uri parameter which enables
     * the request to be passed by reference, as described in section 6.2. Passing a Request Object by Reference of
     * the OpenID Connect spec. The request_uri value is a URL referencing a resource containing a Request Object
     * value, which is a JWT containing the request parameters. This URL MUST use the https scheme.
     *
     * @param request - The HttpServletRequest
     * @return - The Authentication object
     */
    @Override
    public Authentication convert(HttpServletRequest request) {
        log.info("CustomAuthorizationRequestConverter.convert");

        String requestUri = request.getParameter("request_uri");
        String clientId = request.getParameter("client_id");

        if (requestUri != null && clientId != null) {
            // Check if client_id is in the allowed list
            if (!isClientIdAllowed(clientId)) {
                throw new UnauthorizedClientException("The following client ID is not authorized: " + clientId);
            }

            // Retrieve the JWT from the request_uri
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest httpRequest = HttpRequest.newBuilder()
                    .uri(URI.create(requestUri))
                    .GET()
                    .build();
            HttpResponse<String> httpResponse;
            try {
                httpResponse = client.send(httpRequest, HttpResponse.BodyHandlers.ofString());
            } catch (IOException | InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new RequestObjectRetrievalException(e.getMessage());
            }

            // Validate the JWT and create a custom authentication token
            try {
                String jwt = httpResponse.body();
                JWSObject jwsObject = JWSObject.parse(jwt);

                // Use DIDService to get the public key bytes
                byte[] publicKeyBytes = didService.getPublicKeyBytesFromDid(clientId);

                // Use JWTService to verify the JWT signature
                jwtService.verifyJWTSignature(jwt, publicKeyBytes);

                // Validate OAuth 2.0 parameters against the JWT
                if (!validateOAuth2Parameters(request, jwsObject)) {
                    throw new RequestMismatchException("OAuth 2.0 parameters do not match the JWT claims.");
                }

                // Create and return a valid OAuth2 authentication token
                // Implement the creation of your OAuth2AuthorizationCodeRequestAuthenticationToken or similar

            } catch (ParseException e) {
                throw new RequestObjectRetrievalException(e.getMessage());
            }
        }
        return null; // Return null if conversion fails
    }

    private boolean isClientIdAllowed(String clientId) {
        try {
            List<String> allowedClientIds = Files.readAllLines(Paths.get(CLIENT_ID_FILE_PATH));
            return allowedClientIds.contains(clientId);
        } catch (IOException e) {
            throw new RuntimeException("Error reading client ID list.", e);
        }
    }

    private boolean validateOAuth2Parameters(HttpServletRequest request, JWSObject jwsObject) {
        try {
            String jwtPayload = jwsObject.getPayload().toString();
            JSONObject jwtClaims = new JSONObject(jwtPayload);

            String requestResponseType = request.getParameter("response_type");
            String requestClientId = request.getParameter("client_id");
            String requestScope = request.getParameter("scope");

            String jwtResponseType = jwtClaims.optString("response_type");
            String jwtClientId = jwtClaims.optString("client_id");
            String jwtScope = jwtClaims.optString("scope");

            // Ensure that required OAuth 2.0 parameters match those in the JWT
            return requestResponseType.equals(jwtResponseType)
                    && requestClientId.equals(jwtClientId)
                    && requestScope.contains("openid")
                    && requestScope.equals(jwtScope);
        } catch (JSONException e) {
            throw new RuntimeException("Invalid JWT payload.", e);
        }
    }


}
