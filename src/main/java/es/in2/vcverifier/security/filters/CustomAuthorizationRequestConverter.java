package es.in2.vcverifier.security.filters;

import com.nimbusds.jose.JWSObject;
import es.in2.vcverifier.exception.RequestObjectRetrievalException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.text.ParseException;

@Slf4j
public class CustomAuthorizationRequestConverter implements AuthenticationConverter {

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

        // Retrieve the request object from the request_uri parameter
        String requestUri = request.getParameter("request_uri");
        // Logic to retrieve and validate the JWT from the request_uri
        if(requestUri != null) {
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


            // Realiza la validación del JWT y crea un token de autenticación personalizado
            try {
                String jwt = httpResponse.body();
                JWSObject jwsObject = JWSObject.parse(jwt);
                // Validate the JWT with the public key of the did:key of the client_id
                // Get the payload of the JWT, which contains the request parameters
            } catch (ParseException e) {
                throw new RequestObjectRetrievalException(e.getMessage());
            }

            // OAuth2AuthorizationCodeRequestAuthenticationToken, por ejemplo


        }
        return null; // Si no se puede convertir, devolver null
    }

}
