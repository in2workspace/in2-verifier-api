package es.in2.verifier.domain.exception;

public class NotSupportedDidException extends RuntimeException {

    public NotSupportedDidException(String message, Throwable cause) {
        super(message, cause);
    }

    public NotSupportedDidException(String message) {
        super(message);
    }

}
