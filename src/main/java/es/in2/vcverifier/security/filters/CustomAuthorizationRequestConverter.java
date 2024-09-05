package es.in2.vcverifier.security.filters;

import com.nimbusds.jose.JWSObject;
import es.in2.vcverifier.exception.RequestMismatchException;
import es.in2.vcverifier.exception.RequestObjectRetrievalException;
import es.in2.vcverifier.exception.UnauthorizedClientException;
import es.in2.vcverifier.service.DIDService;
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
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.ParseException;
import java.util.List;

import static es.in2.vcverifier.util.Constants.*;

@Slf4j
@RequiredArgsConstructor
public class CustomAuthorizationRequestConverter implements AuthenticationConverter {

    private static final String CLIENT_ID_FILE_PATH = "src/main/resources/static/client_id_list.txt";
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

        String requestUri = request.getParameter(REQUEST_URI); // request_uri parameter
        String jwt = request.getParameter("request");     // request parameter (JWT directly)
        String clientId = request.getParameter(CLIENT_ID);     // client_id parameter

        if (clientId == null) {
            throw new IllegalArgumentException("Client ID is required.");
        }

        // Check if client_id is in the allowed list
        if (!isClientIdAllowed(clientId)) {
            throw new UnauthorizedClientException("The following client ID is not authorized: " + clientId);
        }

        // Case 1: JWT is directly provided in the "request" parameter
        if (jwt != null) {
            log.info("JWT found directly in request parameter.");
        }

        // Case 2: JWT needs to be retrieved via "request_uri"
        else if (requestUri != null) {
            log.info("Retrieving JWT from request_uri: " + requestUri);

            // Retrieve the JWT from the request_uri via HTTP GET
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest httpRequest = HttpRequest.newBuilder()
                    .uri(URI.create(requestUri))
                    .GET()
                    .build();
            HttpResponse<String> httpResponse;
            try {
                httpResponse = client.send(httpRequest, HttpResponse.BodyHandlers.ofString());
                jwt = httpResponse.body(); // Set the JWT from the HTTP response body
            } catch (IOException | InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new RequestObjectRetrievalException(e.getMessage());
            }
        } else {
            // If neither request nor request_uri is provided, throw an exception
            throw new IllegalArgumentException("Either 'request' or 'request_uri' must be provided.");
        }

        // Validate the JWT and create a custom authentication token
        try {
            JWSObject jwsObject = JWSObject.parse(jwt);

            // Validate OAuth 2.0 parameters against the JWT
            if (!validateOAuth2Parameters(request, jwsObject)) {
                throw new RequestMismatchException("OAuth 2.0 parameters do not match the JWT claims.");
            }
            // Use DIDService to get the public key bytes
            byte[] publicKeyBytes = didService.getPublicKeyBytesFromDid(clientId);

            // Use JWTService to verify the JWT signature
            jwtService.verifyJWTSignature(jwt, publicKeyBytes);

        } catch (ParseException e) {
            throw new RequestObjectRetrievalException(e.getMessage());
        }

        return null;
    }

    private boolean isClientIdAllowed(String clientId) {
        try {
            Path path = Paths.get(CLIENT_ID_FILE_PATH).toAbsolutePath();
            List<String> allowedClientIds = Files.readAllLines(path);
            return allowedClientIds.contains(clientId);
        } catch (IOException e) {
            throw new RuntimeException("Error reading client ID list.", e);
        }
    }


    private boolean validateOAuth2Parameters(HttpServletRequest request, JWSObject jwsObject) {
        try {
            String jwtPayload = jwsObject.getPayload().toString();
            JSONObject jwtClaims = new JSONObject(jwtPayload);

            String requestResponseType = request.getParameter(RESPONSE_TYPE);
            String requestClientId = request.getParameter(CLIENT_ID);
            String requestScope = request.getParameter(SCOPE);

            String jwtResponseType = jwtClaims.optString(RESPONSE_TYPE);
            String jwtClientId = jwtClaims.optString(CLIENT_ID);
            String jwtScope = jwtClaims.optString(SCOPE);

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
