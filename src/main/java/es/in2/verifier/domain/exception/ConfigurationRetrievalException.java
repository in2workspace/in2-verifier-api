package es.in2.verifier.domain.exception;

public class ConfigurationRetrievalException extends RuntimeException {

    public ConfigurationRetrievalException(String message, Throwable cause) {
        super(message, cause);
    }

    public ConfigurationRetrievalException(String message) {
        super(message);
    }

}
