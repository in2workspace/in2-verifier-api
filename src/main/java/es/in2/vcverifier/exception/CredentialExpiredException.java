package es.in2.vcverifier.exception;

public class CredentialExpiredException extends RuntimeException {
    public CredentialExpiredException(String message) {
        super(message);
    }
}
