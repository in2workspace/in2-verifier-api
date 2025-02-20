package es.in2.vcverifier.oid4vp.controller;

import es.in2.vcverifier.controller.ClientErrorController;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.ui.Model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ClientErrorControllerTest {

    @InjectMocks
    private ClientErrorController clientErrorController;

    @Mock
    private VerifierUiLoginUrisProperties verifierUiLoginUrisProperties;

    @Mock
    private CustomizationConfig customizationConfig;

    @Mock
    private Model model;

    private static final String PRIMARY_COLOR = "#14274A";
    private static final String PRIMARY_CONTRAST_COLOR = "#ffffff";
    private static final String SECONDARY_COLOR = "#00ADD3";
    private static final String SECONDARY_CONTRAST_COLOR = "#000000";
    private static final String FAVICON_SRC = "faviconSrcValue";


    @Test
    void showErrorPage_withValidParameters_shouldReturnViewNameAndAddAttributesToModel() {
        // Arrange
        String errorCode = "ERROR_CODE_123";
        String errorMessage = "An error occurred during client authentication.";
        String clientUrl = "https://client.example.com";
        String supportUri = "https://support.example.com";
        String originalRequestURL = "https://original.example.com";


        when(verifierUiLoginUrisProperties.supportUri()).thenReturn(supportUri);
        when(customizationConfig.getPrimaryColor()).thenReturn(PRIMARY_COLOR);
        when(customizationConfig.getPrimaryContrastColor()).thenReturn(PRIMARY_CONTRAST_COLOR);
        when(customizationConfig.getSecondaryColor()).thenReturn(SECONDARY_COLOR);
        when(customizationConfig.getSecondaryContrastColor()).thenReturn(SECONDARY_CONTRAST_COLOR);
        when(customizationConfig.getFaviconSrc()).thenReturn(FAVICON_SRC);

        // Act
        String viewName = clientErrorController.showErrorPage(errorCode, errorMessage, clientUrl, originalRequestURL ,model);

        // Assert
        assertEquals("client-authentication-error", viewName);

        verify(model).addAttribute("errorCode", errorCode);
        verify(model).addAttribute("errorMessage", errorMessage);
        verify(model).addAttribute("clientUrl", clientUrl);
        verify(model).addAttribute("supportUri", supportUri);
        verify(model).addAttribute("originalRequestURL", originalRequestURL);
        verify(model).addAttribute("primary", PRIMARY_COLOR);
        verify(model).addAttribute("primaryContrast", PRIMARY_CONTRAST_COLOR);
        verify(model).addAttribute("secondary", SECONDARY_COLOR);
        verify(model).addAttribute("secondaryContrast", SECONDARY_CONTRAST_COLOR);
        verify(model).addAttribute("faviconSrc", FAVICON_SRC);

    }

    @Test
    void showErrorPage_withNullSupportUri_shouldAddNullSupportUriToModel() {
        // Arrange
        String errorCode = "ERROR_CODE_456";
        String errorMessage = "Another error occurred.";
        String clientUrl = "https://client.example.com";
        String originalRequestURL = "https://original.example.com";
        when(verifierUiLoginUrisProperties.supportUri()).thenReturn(null);

        // Act
        String viewName = clientErrorController.showErrorPage(errorCode, errorMessage, clientUrl, originalRequestURL, model);

        // Assert
        assertEquals("client-authentication-error", viewName);

        verify(model).addAttribute("errorCode", errorCode);
        verify(model).addAttribute("errorMessage", errorMessage);
        verify(model).addAttribute("clientUrl", clientUrl);
        verify(model).addAttribute("supportUri", null);
        verify(model).addAttribute("originalRequestURL", originalRequestURL);
    }

    @Test
    void showErrorPage_withNullParameters_shouldAddNullValuesToModel() {
        // Arrange
        String supportUri = "https://support.example.com";

        when(verifierUiLoginUrisProperties.supportUri()).thenReturn(supportUri);

        // Act
        String viewName = clientErrorController.showErrorPage(null, null, null, null,model);

        // Assert
        assertEquals("client-authentication-error", viewName);

        verify(model).addAttribute("errorCode", null);
        verify(model).addAttribute("errorMessage", null);
        verify(model).addAttribute("clientUrl", null);
        verify(model).addAttribute("originalRequestURL", null);
        verify(model).addAttribute("supportUri", supportUri);
    }
}

