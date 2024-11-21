package es.in2.verifier.exception;

public class JWTVerificationException extends RuntimeException {

    public JWTVerificationException(String message) {
        super(message);
    }

}
