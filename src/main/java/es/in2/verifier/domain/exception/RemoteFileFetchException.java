package es.in2.verifier.domain.exception;

public class RemoteFileFetchException extends RuntimeException {
    public RemoteFileFetchException(String message) {
        super(message);
    }

    public RemoteFileFetchException(String message, Throwable cause) {
        super(message, cause);
    }
}
