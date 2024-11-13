package es.in2.verifier.infrastructure.controller;

import es.in2.verifier.domain.exception.*;
import es.in2.verifier.domain.model.dto.GlobalErrorMessage;
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

    @ExceptionHandler(NotSupportedDidException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public void handleNotSupportedDidException(NotSupportedDidException e) {
        log.error("Resource not found", e);
    }


    @ExceptionHandler(ResourceNotFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public GlobalErrorMessage handleResourceNotFoundException(ResourceNotFoundException e) {
        log.error("Resource not found", e);
        return new GlobalErrorMessage("", "", "");
    }

    @ExceptionHandler(NoSuchElementException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public GlobalErrorMessage handleNoSuchElementException(NoSuchElementException e) {
        log.error("Element not found", e);
        return new GlobalErrorMessage("", "", "");
    }

    @ExceptionHandler(QRCodeGenerationException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public GlobalErrorMessage handleQRCodeGenerationException(QRCodeGenerationException e) {
        log.error("QR Code Generation Failed", e);
        return new GlobalErrorMessage("QR Code Generation Failed", "", "");
    }

    @ExceptionHandler(CredentialRevokedException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public GlobalErrorMessage handleException(CredentialRevokedException e) {
        log.error("The credential has been revoked: ", e);
        return new GlobalErrorMessage("Verifiable presentation failed", "", "");
    }

    @ExceptionHandler(MismatchOrganizationIdentifierException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public GlobalErrorMessage handleException(MismatchOrganizationIdentifierException e) {
        log.error("The organization identifier of the cert does not match the organization identifier from the credential payload: ", e);
        return new GlobalErrorMessage("", "", "");
    }

    @ExceptionHandler(Exception.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public GlobalErrorMessage handleException(Exception e) {
        log.error("An unexpected error occurred: ", e);
        return new GlobalErrorMessage("", "", "");
    }

}

