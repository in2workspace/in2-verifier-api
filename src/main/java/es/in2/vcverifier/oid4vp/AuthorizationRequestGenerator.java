package es.in2.vcverifier.oid4vp;

public class AuthorizationRequestGenerator {

    public String generateAuthorizationRequest() {
        // Generar JWT firmado usando la biblioteca Nimbus o similar
        String jwt = generateSignedJWT();
        return "openid4vp://?client_id=https%3A%2F%2Fverifier.dome-marketplace.org"
                + "&request_uri=https%3A%2F%2Fverifier.dome-marketplace.org%2fauthorization-request%2F567545564";
    }

    private String generateSignedJWT() {
        // Lógica para generar y firmar el JWT
        String jwtToken = null;
        return jwtToken;
    }

}
