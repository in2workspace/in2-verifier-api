package es.in2.vcverifier.exception;

public class LoginTimeoutException extends  RuntimeException {
    public LoginTimeoutException(String message){
        super(message);
    }
}
