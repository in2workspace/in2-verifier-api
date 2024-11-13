package es.in2.verifier.domain.exception;

public class FailedCommunicationException extends RuntimeException {

    public FailedCommunicationException(String message) {
        super(message);
    }

}