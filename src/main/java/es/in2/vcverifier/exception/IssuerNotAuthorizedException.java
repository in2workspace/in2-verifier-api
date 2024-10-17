package es.in2.vcverifier.exception;

public class IssuerNotAuthorizedException extends RuntimeException {
    public IssuerNotAuthorizedException(String message) {
        super(message);
    }
}
