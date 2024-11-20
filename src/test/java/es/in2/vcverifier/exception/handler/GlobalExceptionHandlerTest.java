package es.in2.vcverifier.exception.handler;

import es.in2.vcverifier.exception.*;
import es.in2.vcverifier.model.GlobalErrorMessage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.NoSuchElementException;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest
class GlobalExceptionHandlerTest {

    private GlobalExceptionHandler globalExceptionHandler;

    @BeforeEach
    void setUp() {
        globalExceptionHandler = new GlobalExceptionHandler();
    }

    @Test
    void testHandleResourceNotFoundException() {
        ResourceNotFoundException exception = new ResourceNotFoundException("Resource not found");

        GlobalErrorMessage response = globalExceptionHandler.handleResourceNotFoundException(exception);

        assertEquals("", response.title());
        assertEquals("", response.message());
        assertEquals("", response.path());
    }

    @Test
    void testHandleNoSuchElementException() {
        NoSuchElementException exception = new NoSuchElementException("Element not found");

        GlobalErrorMessage response = globalExceptionHandler.handleNoSuchElementException(exception);

        assertEquals("", response.title());
        assertEquals("", response.message());
        assertEquals("", response.path());
    }

    @Test
    void testHandleQRCodeGenerationException() {
        QRCodeGenerationException exception = new QRCodeGenerationException("QR Code Generation Failed");

        GlobalErrorMessage response = globalExceptionHandler.handleQRCodeGenerationException(exception);

        assertEquals("QR Code Generation Failed", response.title());
        assertEquals("", response.message());
        assertEquals("", response.path());
    }

    @Test
    void testHandleCredentialRevokedException() {
        CredentialRevokedException exception = new CredentialRevokedException("Credential revoked");

        GlobalErrorMessage response = globalExceptionHandler.handleException(exception);

        assertEquals("Verifiable presentation failed", response.title());
        assertEquals("", response.message());
        assertEquals("", response.path());
    }

    @Test
    void testHandleMismatchOrganizationIdentifierException() {
        MismatchOrganizationIdentifierException exception = new MismatchOrganizationIdentifierException("Mismatch org identifier");

        GlobalErrorMessage response = globalExceptionHandler.handleException(exception);

        assertEquals("", response.title());
        assertEquals("", response.message());
        assertEquals("", response.path());
    }

    @Test
    void testHandleGenericException() {
        Exception exception = new Exception("Generic error");

        GlobalErrorMessage response = globalExceptionHandler.handleException(exception);

        assertEquals("", response.title());
        assertEquals("", response.message());
        assertEquals("", response.path());
    }

    @Test
    void testHandleInvalidVPtokenException() {
        InvalidVPtokenException exception = new InvalidVPtokenException("Invalid VP token");

        GlobalErrorMessage response = globalExceptionHandler.handleException(exception);

        assertEquals("VP token is not valid", response.title());
        assertEquals("Invalid VP token", response.message());
        assertEquals("", response.path());
    }
}