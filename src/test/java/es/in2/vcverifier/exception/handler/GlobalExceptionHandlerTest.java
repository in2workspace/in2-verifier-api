package es.in2.vcverifier.exception.handler;

import es.in2.vcverifier.exception.*;
import es.in2.vcverifier.model.GlobalErrorMessage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.NoSuchElementException;

import static org.assertj.core.api.Assertions.assertThat;

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

        assertThat(response.title()).isEmpty();
        assertThat(response.message()).isEmpty();
        assertThat(response.path()).isEmpty();
    }

    @Test
    void testHandleNoSuchElementException() {
        NoSuchElementException exception = new NoSuchElementException("Element not found");

        GlobalErrorMessage response = globalExceptionHandler.handleNoSuchElementException(exception);

        assertThat(response.title()).isEmpty();
        assertThat(response.message()).isEmpty();
        assertThat(response.path()).isEmpty();
    }

    @Test
    void testHandleQRCodeGenerationException() {
        QRCodeGenerationException exception = new QRCodeGenerationException("QR Code Generation Failed");

        GlobalErrorMessage response = globalExceptionHandler.handleQRCodeGenerationException(exception);

        assertThat(response.title()).isEqualTo("QR Code Generation Failed");
        assertThat(response.message()).isEmpty();
        assertThat(response.path()).isEmpty();
    }

    @Test
    void testHandleCredentialRevokedException() {
        CredentialRevokedException exception = new CredentialRevokedException("Credential revoked");

        GlobalErrorMessage response = globalExceptionHandler.handleException(exception);

        assertThat(response.title()).isEqualTo("Verifiable presentation failed");
        assertThat(response.message()).isEmpty();
        assertThat(response.path()).isEmpty();
    }

    @Test
    void testHandleMismatchOrganizationIdentifierException() {
        MismatchOrganizationIdentifierException exception = new MismatchOrganizationIdentifierException("Mismatch org identifier");

        GlobalErrorMessage response = globalExceptionHandler.handleException(exception);

        assertThat(response.title()).isEmpty();
        assertThat(response.message()).isEmpty();
        assertThat(response.path()).isEmpty();
    }

    @Test
    void testHandleGenericException() {
        Exception exception = new Exception("Generic error");

        GlobalErrorMessage response = globalExceptionHandler.handleException(exception);

        assertThat(response.title()).isEmpty();
        assertThat(response.message()).isEmpty();
        assertThat(response.path()).isEmpty();
    }

    @Test
    void testHandleInvalidVPtokenException() {
        InvalidVPtokenException exception = new InvalidVPtokenException("Invalid VP token");

        GlobalErrorMessage response = globalExceptionHandler.handleException(exception);

        assertThat(response.title()).isEqualTo("VP token is not valid");
        assertThat(response.message()).isEqualTo("Invalid VP token");
        assertThat(response.path()).isEmpty();
    }
}