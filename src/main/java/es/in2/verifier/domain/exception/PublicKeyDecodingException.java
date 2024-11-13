package es.in2.verifier.domain.exception;

public class PublicKeyDecodingException extends RuntimeException {
    public PublicKeyDecodingException(String message) {
        super(message);
    }

    public PublicKeyDecodingException(String message, Throwable cause) {
        super(message, cause);
    }
}
