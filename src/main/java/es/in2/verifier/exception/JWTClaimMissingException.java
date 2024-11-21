package es.in2.verifier.exception;

public class JWTClaimMissingException extends RuntimeException{

    public JWTClaimMissingException(String message) {
        super(message);
    }

}
