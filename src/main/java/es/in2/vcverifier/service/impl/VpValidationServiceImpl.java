package es.in2.vcverifier.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.model.KeyType;
import es.in2.vcverifier.model.LEARCredentialEmployee;
import es.in2.vcverifier.service.DIDService;
import es.in2.vcverifier.service.JWTService;
import es.in2.vcverifier.service.VpValidationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.*;
import org.springframework.stereotype.Service;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
            PublicKey certificatePubKey = extractPubKeyAndVerifyCertificate(vcHeader, credentialIssuerDid.substring("did:elsi:".length())); // Extract public key from x5c certificate and validate OrganizationIdentifier

//            jwtService.verifyJWTSignature(jwtCredential.serialize(), certificatePubKey, KeyType.RSA);  // Use JWTService to verify signature

            // Step 4: Extract the mandateeId from the Verifiable Credential
            LEARCredentialEmployee learCredentialEmployee = mapCredentialToLEARCredentialEmployee(jwtCredential.getPayload().toJSONObject().get("vc"));
            String mandateeId = learCredentialEmployee.credentialSubject().mandate().mandatee().id();

            if (!isParticipantIdAllowed(mandateeId)) {
                log.error("Mandatee ID {} is not in the allowed list", mandateeId);
                return false;
            }
            log.info("Mandatee ID {} is valid and allowed", mandateeId);

            // Step 5: Validate the VP's signature with the DIDService (the DID of the holder of the VP)
            PublicKey holderPublicKey = didService.getPublicKeyFromDid(mandateeId); // Get the holder's public key in bytes
            jwtService.verifyJWTSignature(verifiablePresentation, holderPublicKey, KeyType.EC); // Validate the VP was signed by the holder DID

            return true; // All validations passed
        } catch (Exception e) {
            log.error("Error during VP validation: {}", e.getMessage());
            return false;
        }
    }


    private LEARCredentialEmployee mapCredentialToLEARCredentialEmployee(Object vcObject) {
        try {
            // Convert the Object to a Map or directly to the LEARCredentialEmployee class
            return objectMapper.convertValue(vcObject, LEARCredentialEmployee.class);
        } catch (IllegalArgumentException e) {
            throw new RuntimeException("Error converting VC to LEARCredentialEmployee", e);
        }
    }

    private SignedJWT extractFirstVerifiableCredential(String verifiablePresentation) {
        try {
            // Parse the Verifiable Presentation (VP) JWT
            SignedJWT vpSignedJWT = SignedJWT.parse(verifiablePresentation);

            // Extract the "vp" claim
            Object vpClaim = vpSignedJWT.getJWTClaimsSet().getClaim("vp");

            Object vcClaim = getVcClaim(vpClaim);

            // Extract the first credential if it's a list or if it's a string
            Object firstCredential = getFirstCredential(vcClaim);

            // Parse and return the first Verifiable Credential as SignedJWT
            return SignedJWT.parse((String) firstCredential);

        } catch (ParseException e) {
            throw new RuntimeException("Error parsing the Verifiable Presentation or Verifiable Credential", e);
        }
    }

    private static Object getVcClaim(Object vpClaim) {
        if (vpClaim == null) {
            throw new RuntimeException("The 'vp' claim was not found in the Verifiable Presentation");
        }

        // Ensure that vpClaim is an instance of Map (JSON object)
        if (!(vpClaim instanceof Map<?, ?> vpMap)) {
            throw new RuntimeException("The 'vp' claim is not a valid object");
        }

        // Extract the "verifiableCredential" claim inside "vp"
        Object vcClaim = vpMap.get("verifiableCredential");

        if (vcClaim == null) {
            throw new RuntimeException("The 'verifiableCredential' claim was not found within 'vp'");
        }

        return vcClaim;
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


    private PublicKey extractPubKeyAndVerifyCertificate(Map<String, Object> vcHeader, String expectedOrgId) throws Exception {
        // Retrieve the x5c claim (certificate chain)
        Object x5cObj = vcHeader.get("x5c");

        if (!(x5cObj instanceof List<?> x5c)) {
            throw new IllegalArgumentException("The x5c claim is not a valid list");
        }

        if (x5c.isEmpty()) {
            throw new IllegalArgumentException("No certificate (x5c) found in JWT header");
        }

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

        for (Object certBase64Obj : x5c) {
            if (!(certBase64Obj instanceof String)) {
                log.error("Invalid certificate format in x5c");
                continue; // Skip invalid entries and continue with the next one
            }

            // Decode each certificate
            byte[] certBytes = Base64.getDecoder().decode((String) certBase64Obj);
            X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(new java.io.ByteArrayInputStream(certBytes));

            // Extract the DN (Distinguished Name)
            X500Principal subject = certificate.getSubjectX500Principal();
            String distinguishedName = subject.getName();
            log.info("Extracted DN: {}", distinguishedName);

            // Try to extract the organizationIdentifier from the DN
            String orgIdentifierFromDN = extractOrganizationIdentifierFromDN(distinguishedName);
            if (orgIdentifierFromDN != null && orgIdentifierFromDN.equals("VATEU-B99999999")) {
                log.info("Found matching organization identifier in DN: {}", orgIdentifierFromDN);
                return certificate.getPublicKey(); // Return the public key from the certificate
            }

        }
        throw new Exception("Organization Identifier not found in certificates.");
    }

    // Helper method to extract and decode the organizationIdentifier from the DN
    private String extractOrganizationIdentifierFromDN(String distinguishedName) {
        log.info("Extracting organizationIdentifier from DN: {}", distinguishedName);

        // Use a regular expression to find the 2.5.4.97 OID in the DN
        Pattern pattern = Pattern.compile("2\\.5\\.4\\.97=#([0-9A-F]+)", Pattern.CASE_INSENSITIVE);
        Matcher matcher = pattern.matcher(distinguishedName);

        if (matcher.find()) {
            String hexValue = matcher.group(1);
            log.info("Extracted hex value for organizationIdentifier: {}", hexValue);

            // Decode the hex string properly as ASN.1 encoded value
            return decodeHexToReadableString(hexValue);
        } else {
            log.warn("OID 2.5.4.97 not found in DN: {}", distinguishedName);
        }
        return null; // Return null if organizationIdentifier is not found
    }


    // Method to properly decode the hex value as an ASN.1 structure
    private String decodeHexToReadableString(String hexValue) {
        try {
            byte[] octets = hexStringToByteArray(hexValue);
            try (ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(octets))) {
                ASN1Primitive asn1Primitive = asn1InputStream.readObject();

                if (asn1Primitive instanceof ASN1OctetString octetString) {
                    return new String(octetString.getOctets(), StandardCharsets.UTF_8); // Try to decode as UTF-8
                } else if (asn1Primitive instanceof ASN1PrintableString) {
                    return ((ASN1PrintableString) asn1Primitive).getString();
                } else if (asn1Primitive instanceof ASN1UTF8String) {
                    return ((ASN1UTF8String) asn1Primitive).getString();
                } else if (asn1Primitive instanceof ASN1IA5String) {
                    return ((ASN1IA5String) asn1Primitive).getString();
                } else {
                    log.warn("Unrecognized ASN.1 type: {}", asn1Primitive.getClass().getSimpleName());
                }
            }
        } catch (IOException e) {
            log.error("Error decoding hex value to readable string", e);
        }
        return null;
    }


    // Convert hex string to byte array
    private byte[] hexStringToByteArray(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i+1), 16));
        }
        return data;
    }
}



