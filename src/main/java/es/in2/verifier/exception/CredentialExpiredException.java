package es.in2.verifier.exception;

public class CredentialExpiredException extends RuntimeException {
    public CredentialExpiredException(String message) {
        super(message);
    }
}
