package es.in2.vcverifier.util;

public class Constants {
    private Constants() {
        throw new IllegalStateException("Utility class");
    }

    public static final String CLIENT_ID = "client_id";
    public static final String REQUEST_URI = "request_uri";
    public static final String RESPONSE_TYPE= "response_type";
    public static final String SCOPE = "scope";
    public static final String AUTHORIZATION_RESPONSE_ENDPOINT= "http://localhost:9000/oid4vp/auth-response";
    public static final long MSB = 0x80L;
    public static final long MSBALL = 0xFFFFFF80L;
}
