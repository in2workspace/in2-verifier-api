package es.in2.verifier.exception;

public class IssuerNotAuthorizedException extends RuntimeException {
    public IssuerNotAuthorizedException(String message) {
        super(message);
    }
}
