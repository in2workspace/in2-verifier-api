package es.in2.verifier.exception;

public class CredentialRevokedException extends RuntimeException {
    public CredentialRevokedException(String message) {
        super(message);
    }
}

