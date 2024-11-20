package es.in2.vcverifier.util;

public class Constants {
    private Constants() {
        throw new IllegalStateException("Utility class");
    }

    public static final String CLIENT_ID = "client_id";
    public static final String REQUEST_URI = "request_uri";
    public static final String RESPONSE_TYPE= "response_type";
    public static final String SCOPE = "scope";
    public static final String AUTHORIZATION_RESPONSE_ENDPOINT= "/oid4vp/auth-response";
    public static final String DID_ELSI_PREFIX = "did:elsi:";
    public static final String MINUTES = "MINUTES";
    public static final String LOGIN_ENDPOINT = "/login";
    public static final String CLIENT_ERROR_ENDPOINT = "/client-error";
    public static final String REQUIRED_EXTERNAL_USER_AUTHENTICATION = "required_external_user_authentication";
    public static final String INVALID_CLIENT_AUTHENTICATION = "invalid_client_authentication";
    public static final String LOG_ERROR_FORMAT = "{} - {}";
    public static final long MSB = 0x80L;
    public static final long MSBALL = 0xFFFFFF80L;

}
