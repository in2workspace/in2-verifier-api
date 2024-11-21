package es.in2.verifier.exception;

public class JWTParsingException extends RuntimeException{

    public JWTParsingException(String message) {
        super(message);
    }

}
