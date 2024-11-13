package es.in2.verifier.domain.exception;

public class ClientLoadingException extends RuntimeException{

    public ClientLoadingException(String message, Throwable cause) {
        super(message, cause);
    }
}
