package es.in2.verifier.exception;

public class CredentialNotActiveException extends RuntimeException {
    public CredentialNotActiveException(String message) {
        super(message);
    }
}
