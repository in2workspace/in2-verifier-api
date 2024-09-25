package es.in2.vcverifier.exception;

public class IssuerOrParticipantIdException extends RuntimeException {
    public IssuerOrParticipantIdException(String message) {
        super(message);
    }

    public IssuerOrParticipantIdException(String message, Throwable cause) {
        super(message, cause);
    }
}
