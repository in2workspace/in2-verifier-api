package es.in2.vcverifier.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.model.LEARCredentialEmployee;
import es.in2.vcverifier.service.DIDService;
import es.in2.vcverifier.service.JWTService;
import es.in2.vcverifier.service.VpValidationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 *This class contains basic validation steps for the scope of validating a Verifiable Presentation (VP)
 * that includes a LEARCredential, following the technical guidelines described in the DOME document.
 * The current implementation includes:
 * - Validation of the Verifiable Credential (VC) issuer.
 * - Verification of the signature using the public key from the JWT.
 * - Extraction and validation of the mandatee ID from the credential subject.
 * - Verification that the VP is signed by the correct DID.
 * In future versions, additional verifications will be added to enhance the validation process.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class VpValidationServiceImpl implements VpValidationService {

    private final DIDService didService; // Service for handling trusted DIDs
    private final JWTService jwtService; // Service for JWT-related validations
    private final ObjectMapper objectMapper;
    private static final String ISSUER_ID_FILE_PATH = "src/main/resources/static/issuer_id_list.txt";
    private static final String PARTICIPANTS_ID_FILE_PATH = "src/main/resources/static/participants_id_list.txt";



    @Override
    public boolean validateVerifiablePresentation(String verifiablePresentation) {
        try {
            // Step 1: Extract the Verifiable Credential (VC) from the VP (JWT)
            SignedJWT jwtCredential = extractFirstVerifiableCredential(verifiablePresentation);

            // Step 2: Validate the issuer
            String credentialIssuerDid = jwtCredential.getPayload().toJSONObject().get("iss").toString();



            if (!isIssuerIdAllowed(credentialIssuerDid)) {
                log.error("Issuer DID {} is not a trusted participant", credentialIssuerDid);
                return false;
            }
            log.info("Issuer DID {} is a trusted participant", credentialIssuerDid);

            // Step 3: Extract the public key from JWT header and verify the signature
            Map<String, Object> vcHeader = jwtCredential.getHeader().toJSONObject();
            PublicKey publicKey = extractAndVerifyCertificate(vcHeader,credentialIssuerDid.substring("did:elsi:".length())); // Extract public key from x5c certificate and validate OrganizationIdentifier
            jwtService.verifyJWTSignature(jwtCredential.serialize(), publicKey.getEncoded());  // Use JWTService to verify signature


            // Step 4: Extract the mandateeId from the Verifiable Credential
            LEARCredentialEmployee learCredentialEmployee = mapCredentialToLEARCredentialEmployee(jwtCredential.getPayload().toJSONObject().get("vc").toString());
            String mandateeId = learCredentialEmployee.credentialSubject().mandate().mandatee().id();

            if (!isParticipantIdAllowed(mandateeId)) {
                log.error("Mandatee ID {} is not in the allowed list", mandateeId);
                return false;
            }
            log.info("Mandatee ID {} is valid and allowed", mandateeId);

            // Step 5: Validate the VP's signature with the DIDService (the DID of the holder of the VP)
            byte[] holderPublicKey = didService.getPublicKeyBytesFromDid(mandateeId); // Get the holder's public key in bytes
            jwtService.verifyJWTSignature(verifiablePresentation, holderPublicKey); // Validate the VP was signed by the holder DID

            return true; // All validations passed
        } catch (Exception e) {
            log.error("Error during VP validation: {}", e.getMessage());
            return false;
        }
    }

    private LEARCredentialEmployee mapCredentialToLEARCredentialEmployee(String learCredential) {
        try {
            return objectMapper.readValue(learCredential, LEARCredentialEmployee.class);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }
    private SignedJWT extractFirstVerifiableCredential(String verifiablePresentation) {
        try {
            // Parse the Verifiable Presentation (VP) JWT
            SignedJWT vpSignedJWT = SignedJWT.parse(verifiablePresentation);

            // Extract the "verifiableCredential" claim, which is expected to be an array
            Object vcClaim = vpSignedJWT.getJWTClaimsSet().getClaim("verifiableCredential");

            Object firstCredential = getFirstCredential(vcClaim);

            // Parse and return the first Verifiable Credential as a SignedJWT
            return SignedJWT.parse((String) firstCredential);

        } catch (ParseException e) {
            throw new RuntimeException("Error extracting Verifiable Credential from Verifiable Presentation", e);
        }
    }

    private static Object getFirstCredential(Object vcClaim) {
        if (!(vcClaim instanceof List<?> verifiableCredentials)) {
            throw new IllegalStateException("The verifiableCredential claim is not an array");
        }

        if (verifiableCredentials.isEmpty()) {
            throw new IllegalStateException("No Verifiable Credential found in Verifiable Presentation");
        }

        // Ensure the first item is a String (JWT in string form)
        Object firstCredential = verifiableCredentials.get(0);
        if (!(firstCredential instanceof String)) {
            throw new IllegalStateException("The first Verifiable Credential is not a valid JWT string");
        }
        return firstCredential;
    }

    private boolean isIssuerIdAllowed(String issuerId) {
        try {
            Path path = Paths.get(ISSUER_ID_FILE_PATH).toAbsolutePath();
            List<String> allowedIssuerIds = Files.readAllLines(path);
            return allowedIssuerIds.contains(issuerId);
        } catch (IOException e) {
            throw new RuntimeException("Error reading issuer ID list.", e);
        }
    }
    private boolean isParticipantIdAllowed(String participantId) {
        try {
            Path path = Paths.get(PARTICIPANTS_ID_FILE_PATH).toAbsolutePath();
            List<String> allowedParticipantIds = Files.readAllLines(path);
            return allowedParticipantIds.contains(participantId);
        } catch (IOException e) {
            throw new RuntimeException("Error reading participant ID list.", e);
        }
    }


    private PublicKey extractAndVerifyCertificate(Map<String, Object> vcHeader, String expectedOrgId) throws Exception {
        // Retrieve the x5c claim (certificate chain)
        Object x5cObj = vcHeader.get("x5c");

        if (!(x5cObj instanceof List<?> x5c)) {
            throw new IllegalArgumentException("The x5c claim is not a valid list");
        }

        if (x5c.isEmpty()) {
            throw new IllegalArgumentException("No certificate (x5c) found in JWT header");
        }

        // Iterate through the certificate chain and check each one
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        for (Object certBase64Obj : x5c) {
            if (!(certBase64Obj instanceof String)) {
                log.error("Invalid certificate format in x5c");
                continue; // Skip invalid entries and continue with the next one
            }

            // Decode each certificate
            byte[] certBytes = Base64.getDecoder().decode((String) certBase64Obj);
            X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(new java.io.ByteArrayInputStream(certBytes));

            // Try extracting the organizationIdentifier from the DN (Distinguished Name)
            X500Principal subject = certificate.getSubjectX500Principal();
            String distinguishedName = subject.getName();
            log.info("Extracted DN: {}", distinguishedName);

            // Check if the expected organization ID is in the DN
            if (distinguishedName.contains("organizationIdentifier=" + expectedOrgId)) {
                log.info("Found matching organization identifier in DN: {}", expectedOrgId);
                return certificate.getPublicKey(); // Return the public key from the certificate
            }

            // If organizationIdentifier might be stored in extensions, extract it from extensions (optional)
            byte[] extValue = certificate.getExtensionValue("2.5.4.97"); // OID for organizationIdentifier
            if (extValue != null) {
                String extractedOrgId = new String(extValue); // Decode this properly, it's usually ASN.1 encoded
                log.info("Extracted organizationIdentifier from extension: {}", extractedOrgId);

                if (extractedOrgId.contains(expectedOrgId)) {
                    log.info("Found matching organization identifier in certificate extension: {}", expectedOrgId);
                    return certificate.getPublicKey(); // Return the public key from the certificate
                }
            }
        }

        // If no certificate matches the expected organization ID, throw an exception
        throw new IllegalStateException("No matching organization identifier found in any certificate in the chain");
    }
}



