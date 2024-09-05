package es.in2.vcverifier.security.filters;

import com.nimbusds.jose.JWSObject;
import es.in2.vcverifier.exception.RequestMismatchException;
import es.in2.vcverifier.exception.RequestObjectRetrievalException;
import es.in2.vcverifier.exception.UnauthorizedClientException;
import es.in2.vcverifier.exception.UnsupportedGrantTypeException;
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

        String grantType = request.getParameter("grant_type");

        if (grantType == null) {
            throw new IllegalArgumentException("grant_type is required.");
        }

        return switch (grantType) {
            case "code" -> handleAuthorizationCodeGrant(request);
            case "client_credentials" ->
                // todo implement M2M logic
                    null;
            default -> throw new UnsupportedGrantTypeException("Unsupported grant_type: " + grantType);
        };
    }

    // Handles logic for the 'authorization_code' grant type
    private Authentication handleAuthorizationCodeGrant(HttpServletRequest request) {
        String clientId = request.getParameter(CLIENT_ID);
        if (clientId == null) {
            throw new IllegalArgumentException("Client ID is required.");
        }

        if (!isClientIdAllowed(clientId)) {
            throw new UnauthorizedClientException("The following client ID is not authorized: " + clientId);
        }

        String jwt = retrieveJwtFromRequest(request);
        validateJwt(request, jwt, clientId);

        return null;  // Replace with actual authentication logic
    }

    // Retrieves JWT either from 'request' or 'request_uri'
    private String retrieveJwtFromRequest(HttpServletRequest request) {
        String jwt = request.getParameter("request");
        if (jwt != null) {
            log.info("JWT found directly in request parameter.");
            return jwt;
        }

        String requestUri = request.getParameter(REQUEST_URI);
        if (requestUri != null) {
            log.info("Retrieving JWT from request_uri: " + requestUri);
            return retrieveJwtFromUri(requestUri);
        }

        throw new IllegalArgumentException("Either 'request' or 'request_uri' must be provided.");
    }

    // Makes HTTP call to retrieve JWT from 'request_uri'
    private String retrieveJwtFromUri(String requestUri) {
        try {
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest httpRequest = HttpRequest.newBuilder()
                    .uri(URI.create(requestUri))
                    .GET()
                    .build();
            HttpResponse<String> httpResponse = client.send(httpRequest, HttpResponse.BodyHandlers.ofString());
            return httpResponse.body();
        } catch (IOException | InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RequestObjectRetrievalException(e.getMessage());
        }
    }

    // Validates the JWT signature and OAuth 2.0 parameters
    private void validateJwt(HttpServletRequest request, String jwt, String clientId) {
        try {
            JWSObject jwsObject = JWSObject.parse(jwt);

            if (!validateOAuth2Parameters(request, jwsObject)) {
                throw new RequestMismatchException("OAuth 2.0 parameters do not match the JWT claims.");
            }

            byte[] publicKeyBytes = didService.getPublicKeyBytesFromDid(clientId);
            jwtService.verifyJWTSignature(jwt, publicKeyBytes);

        } catch (ParseException e) {
            throw new RequestObjectRetrievalException(e.getMessage());
        }
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
