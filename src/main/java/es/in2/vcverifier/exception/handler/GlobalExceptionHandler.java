package es.in2.vcverifier.exception.handler;

import es.in2.vcverifier.exception.CredentialRevokedException;
import es.in2.vcverifier.exception.QRCodeGenerationException;
import es.in2.vcverifier.exception.ResourceNotFoundException;
import es.in2.vcverifier.model.GlobalErrorMessage;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.util.NoSuchElementException;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

    @ExceptionHandler(ResourceNotFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public GlobalErrorMessage handleResourceNotFoundException(ResourceNotFoundException ex) {
        log.error("Resource not found", ex);
        return new GlobalErrorMessage("","","");
    }

    @ExceptionHandler(NoSuchElementException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public GlobalErrorMessage handleNoSuchElementException(NoSuchElementException ex) {
        log.error("Element not found", ex);
        return new GlobalErrorMessage("","","");
    }

    @ExceptionHandler(QRCodeGenerationException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public GlobalErrorMessage handleQRCodeGenerationException(QRCodeGenerationException ex) {
        log.error("QR Code Generation Failed", ex);
        return new GlobalErrorMessage("QR Code Generation Failed","","");
    }

    @ExceptionHandler(CredentialRevokedException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public GlobalErrorMessage handleException(CredentialRevokedException ex) {
        log.error("The credential has been revoked: ", ex);
        return new GlobalErrorMessage("Verifiable presentation failed","","");
    }
    @ExceptionHandler(Exception.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public GlobalErrorMessage handleException(Exception ex) {
        log.error("An unexpected error occurred: ", ex);
        return new GlobalErrorMessage("","","");
    }
}

