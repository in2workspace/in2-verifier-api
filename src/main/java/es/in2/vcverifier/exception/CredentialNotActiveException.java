package es.in2.vcverifier.exception;

public class CredentialNotActiveException extends RuntimeException {
    public CredentialNotActiveException(String message) {
        super(message);
    }
}
