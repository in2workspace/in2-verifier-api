package es.in2.verifier.exception;

public class RemoteFileFetchException extends RuntimeException {
    public RemoteFileFetchException(String message) {
        super(message);
    }

    public RemoteFileFetchException(String message, Throwable cause) {
        super(message, cause);
    }
}
