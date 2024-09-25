package es.in2.vcverifier.exception;

public class CredentialException extends RuntimeException {
    public CredentialException(String message) {
        super(message);
    }

    public CredentialException(String message, Throwable cause) {
        super(message, cause);
    }
}
