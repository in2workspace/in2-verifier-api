package es.in2.vcverifier.service.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.shaded.gson.internal.LinkedTreeMap;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.exception.*;
import es.in2.vcverifier.model.credentials.employee.LEARCredentialEmployee;
import es.in2.vcverifier.model.credentials.machine.LEARCredentialMachine;
import es.in2.vcverifier.model.enums.LEARCredentialType;
import es.in2.vcverifier.model.issuer.IssuerCredentialsCapabilities;
import es.in2.vcverifier.service.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.json.JSONObject;
import org.springframework.stereotype.Service;

import java.security.PublicKey;
import java.text.ParseException;
import java.util.List;
import java.util.Map;

import static es.in2.vcverifier.util.Constants.DID_ELSI_PREFIX;

/**
 * This class contains basic validation steps for the scope of validating a Verifiable Presentation (VP)
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
public class VpServiceImpl implements VpService {

    private final JWTService jwtService;
    private final ObjectMapper objectMapper;
    private final TrustFrameworkService trustFrameworkService;
    private final DIDService didService;
    private final CertificateValidationService certificateValidationService;


    @Override
    public boolean validateVerifiablePresentation(String verifiablePresentation) {
        log.info("Starting validation of Verifiable Presentation");
        try {
            // Step 1: Extract the Verifiable Credential (VC) from the VP (JWT)
            log.debug("VpServiceImpl -- validateVerifiablePresentation -- Extracting first Verifiable Credential from Verifiable Presentation");
            SignedJWT jwtCredential = extractFirstVerifiableCredential(verifiablePresentation);
            Payload payload = jwtService.getPayloadFromSignedJWT(jwtCredential);
            log.debug("VpServiceImpl -- validateVerifiablePresentation -- Successfully extracted the Verifiable Credential payload");

            // Step 2: Validate the credential id is not in the revoked list
            log.debug("VpServiceImpl -- validateVerifiablePresentation -- Validating that the credential is not revoked");
            validateCredentialNotRevoked(payload);
            log.info("Credential is not revoked");

            // Step 3: Validate the issuer
            String credentialIssuerDid = jwtService.getClaimFromPayload(payload, "iss");
            log.debug("VpServiceImpl -- validateVerifiablePresentation -- Retrieved issuer DID from payload: {}", credentialIssuerDid);

            // Step 4: Extract and validate credential types
            List<String> credentialTypes = getCredentialTypes(payload);
            log.debug("VpServiceImpl -- validateVerifiablePresentation -- Credential types extracted: {}", credentialTypes);

            // Step 5: Retrieve the list of issuer capabilities
            log.debug("VpServiceImpl -- validateVerifiablePresentation -- Retrieving issuer capabilities for DID {}", credentialIssuerDid);
            List<IssuerCredentialsCapabilities> issuerCapabilitiesList = trustFrameworkService.getTrustedIssuerListData(credentialIssuerDid);
            log.info("Retrieved issuer capabilities");

            // Step 6: Validate credential type against issuer capabilities
            log.debug("VpServiceImpl -- validateVerifiablePresentation -- Validating credential types against issuer capabilities");
            validateCredentialTypeWithIssuerCapabilities(issuerCapabilitiesList, credentialTypes);
            log.info("Issuer DID {} is a trusted participant", credentialIssuerDid);

            // TODO remove step 7 after the advanced certificate validation component is implemented
            // Step 7: Verify the signature and the organizationId of the credential signature
            // FIXME: comented. need to be implemented when all users has a valid credentials
            // Map<String, Object> vcHeader = jwtCredential.getHeader().toJSONObject();
            // certificateValidationService.extractAndVerifyCertificate(jwtCredential.serialize(),vcHeader, credentialIssuerDid.substring("did:elsi:".length())); // Extract public key from x5c certificate and validate OrganizationIdentifier

            // Step 8: Extract the mandateId from the Verifiable Credential
            String mandatorOrganizationIdentifier = extractMandatorOrganizationIdentifier(credentialTypes, payload);
            log.debug("VpServiceImpl -- validateVerifiablePresentation -- Extracted Mandator Organization Identifier from Verifiable Credential: {}", mandatorOrganizationIdentifier);

            //TODO this must be validated against the participants list, not the issuer list
            // Validate the mandator with trusted issuer service, if is not present the trustedIssuerListService throws an exception
            trustFrameworkService.getTrustedIssuerListData(DID_ELSI_PREFIX + mandatorOrganizationIdentifier);
            log.info("Mandator OrganizationIdentifier {} is valid and allowed", mandatorOrganizationIdentifier);

            // Step 9: Validate the VP's signature with the DIDService (the DID of the holder of the VP)
            String mandateeId = extractMandateeId(credentialTypes, payload);
            PublicKey holderPublicKey = didService.getPublicKeyFromDid(mandateeId); // Get the holder's public key in bytes
            jwtService.verifyJWTWithECKey(verifiablePresentation, holderPublicKey); // Validate the VP was signed by the holder DID
            log.info("VP's signature is valid, holder DID {} confirmed", mandateeId);

            log.info("Verifiable Presentation validation completed successfully");
            return true; // All validations passed
        } catch (Exception e) {
            log.error("Error during VP validation: {}", e.getMessage());
            return false;
        }
    }

    @Override
    public Object getCredentialFromTheVerifiablePresentation(String verifiablePresentation) {
        log.debug("VpServiceImpl -- getCredentialFromTheVerifiablePresentation -- Extracting Verifiable Credential object from Verifiable Presentation");
        // Step 1: Extract the Verifiable Credential (VC) from the VP (JWT)
        SignedJWT jwtCredential = extractFirstVerifiableCredential(verifiablePresentation);
        Payload payload = jwtService.getPayloadFromSignedJWT(jwtCredential);
        return jwtService.getVCFromPayload(payload);
    }

    @Override
    public JsonNode getCredentialFromTheVerifiablePresentationAsJsonNode(String verifiablePresentation) {
        log.debug("VpServiceImpl -- getCredentialFromTheVerifiablePresentationAsJsonNode -- Converting Verifiable Credential to JSON Node format");
        return convertObjectToJSONNode(getCredentialFromTheVerifiablePresentation(verifiablePresentation));
    }

    private List<String> getCredentialTypes(Payload payload) {
        log.debug("VpServiceImpl -- getCredentialTypes -- Extracting credential types from payload");
        // Extract and validate the credential types from the payload
        Object vcFromPayload = jwtService.getVCFromPayload(payload);

        if (vcFromPayload instanceof LinkedTreeMap<?, ?> vcObject) {
            // Use a wildcard generic type to avoid unchecked cast warning
            Object typeObject = vcObject.get("type");

            if (typeObject instanceof List<?> typeList) {
                // Check each element to ensure it's a String
                if (typeList.stream().allMatch(String.class::isInstance)) {
                    // Safely cast the List<?> to List<String>
                    log.info("Credential types successfully extracted: {}", typeList);
                    return typeList.stream().map(String.class::cast).toList();
                } else {
                    log.error("VpServiceImpl -- getCredentialTypes -- Type list elements are not all of type String.");
                    throw new InvalidCredentialTypeException("Type list elements are not all of type String.");
                }
            } else {
                log.error("VpServiceImpl -- getCredentialTypes -- 'type' key does not map to a List.");
                throw new InvalidCredentialTypeException("'type' key does not map to a List.");
            }
        } else {
            log.error("VpServiceImpl -- getCredentialTypes -- VC from payload is not a LinkedTreeMap.");
            throw new InvalidCredentialTypeException("VC from payload is not a LinkedTreeMap.");
        }
    }

    private String extractMandateeId(List<String> credentialTypes, Payload payload) {
        Object vcObject = jwtService.getVCFromPayload(payload);

        if (credentialTypes.contains(LEARCredentialType.LEAR_CREDENTIAL_EMPLOYEE.getValue())) {
            LEARCredentialEmployee learCredentialEmployee = mapCredentialToLEARCredentialEmployee(vcObject);
            return learCredentialEmployee.credentialSubject().mandate().mandatee().id();
        } else if (credentialTypes.contains(LEARCredentialType.LEAR_CREDENTIAL_MACHINE.getValue())) {
            LEARCredentialMachine learCredentialMachine = mapCredentialToLEARCredentialMachine(vcObject);
            return learCredentialMachine.credentialSubject().mandate().mandatee().id();
        } else {
            log.error("VpServiceImpl -- extractMandateeId -- Invalid Credential Type. LEARCredentialEmployee or LEARCredentialMachine required.");
            throw new InvalidCredentialTypeException("Invalid Credential Type. LEARCredentialEmployee or LEARCredentialMachine required.");
        }
    }


    private String extractMandatorOrganizationIdentifier(List<String> credentialTypes, Payload payload) {
        Object vcObject = jwtService.getVCFromPayload(payload);

        if (credentialTypes.contains(LEARCredentialType.LEAR_CREDENTIAL_EMPLOYEE.getValue())) {
            LEARCredentialEmployee learCredentialEmployee = mapCredentialToLEARCredentialEmployee(vcObject);
            return learCredentialEmployee.credentialSubject().mandate().mandator().organizationIdentifier();
        } else if (credentialTypes.contains(LEARCredentialType.LEAR_CREDENTIAL_MACHINE.getValue())) {
            LEARCredentialMachine learCredentialMachine = mapCredentialToLEARCredentialMachine(vcObject);
            return learCredentialMachine.credentialSubject().mandate().mandator().organizationIdentifier();
        } else {
            throw new InvalidCredentialTypeException("Invalid Credential Type. LEARCredentialEmployee or LEARCredentialMachine required.");
        }
    }

    private void validateCredentialTypeWithIssuerCapabilities(List<IssuerCredentialsCapabilities> issuerCapabilitiesList, List<String> credentialTypes) {
        // Iterate over each credential type in the verifiable credential
        for (String credentialType : credentialTypes) {
            // Check if any of the issuer capabilities support this credential type
            boolean isSupported = issuerCapabilitiesList.stream().anyMatch(capability -> capability.credentialsType().equals(credentialType));

            // If we find a matching capability, return from the method
            if (isSupported) {
                return;
            }
        }
        // If none of the credential types are supported, throw an exception
        throw new InvalidCredentialTypeException("Credential types " + credentialTypes + " are not supported by the issuer.");
    }

    private void validateCredentialNotRevoked(Payload payload) {
        log.debug("VpServiceImpl -- validateCredentialNotRevoked -- Checking if credential is in the revoked list");

        Object vcFromPayload = jwtService.getVCFromPayload(payload);

        if (vcFromPayload instanceof LinkedTreeMap<?, ?> vcObject) {
            // Use a wildcard generic type to avoid unchecked cast warning
            Object credentialId = vcObject.get("id").toString();
            List<String> revokedIds = trustFrameworkService.getRevokedCredentialIds();
            if (revokedIds.contains(credentialId)) {
                log.error("VpServiceImpl -- validateCredentialNotRevoked -- Credential ID {} is revoked", credentialId);
                throw new CredentialRevokedException("Credential ID " + credentialId + " is revoked.");
            }
        }
        else {
            log.error("VpServiceImpl -- validateCredentialNotRevoked -- VC from payload is not a LinkedTreeMap.");
            throw new InvalidCredentialTypeException("VC from payload is not a LinkedTreeMap.");
        }
    }


    private JsonNode convertObjectToJSONNode(Object vcObject) throws JsonConversionException {
        JsonNode jsonNode;

        try {
            if (vcObject instanceof Map) {
                // Si el objeto es un Map, lo convertimos directamente a JsonNode
                jsonNode = objectMapper.convertValue(vcObject, JsonNode.class);
            } else if (vcObject instanceof JSONObject) {
                // Si el objeto es un JSONObject, lo convertimos a String y luego a JsonNode
                jsonNode = objectMapper.readTree(vcObject.toString());
            } else {
                throw new JsonConversionException("El tipo del objeto no es compatible para la conversión a JsonNode.");
            }
        } catch (Exception e) {
            throw new JsonConversionException("Error durante la conversión a JsonNode.");
        }
        return jsonNode;
    }


    private LEARCredentialMachine mapCredentialToLEARCredentialMachine(Object vcObject) {
        try {
            return objectMapper.convertValue(vcObject, LEARCredentialMachine.class);
        } catch (IllegalArgumentException e) {
            throw new CredentialMappingException("Error converting VC to LEARCredentialMachine");
        }
    }

    private LEARCredentialEmployee mapCredentialToLEARCredentialEmployee(Object vcObject) {
        try {
            // Convert the Object to a Map or directly to the LEARCredentialEmployee class
            return objectMapper.convertValue(vcObject, LEARCredentialEmployee.class);
        } catch (IllegalArgumentException e) {
            throw new CredentialMappingException("Error converting VC to LEARCredentialEmployee");
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
            throw new JWTParsingException("Error parsing the Verifiable Presentation or Verifiable Credential");
        }
    }

    private static Object getVcClaim(Object vpClaim) {
        if (vpClaim == null) {
            throw new JWTClaimMissingException("The 'vp' claim was not found in the Verifiable Presentation");
        }
        // Ensure that vpClaim is an instance of Map (JSON object)
        if (!(vpClaim instanceof Map<?, ?> vpMap)) {
            throw new JWTClaimMissingException("The 'vp' claim is not a valid object");
        }
        // Extract the "verifiableCredential" claim inside "vp"
        Object vcClaim = vpMap.get("verifiableCredential");
        if (vcClaim == null) {
            throw new JWTClaimMissingException("The 'verifiableCredential' claim was not found within 'vp'");
        }
        return vcClaim;
    }


    private static Object getFirstCredential(Object vcClaim) {
        if (!(vcClaim instanceof List<?> verifiableCredentials)) {
            throw new CredentialException("The verifiableCredential claim is not an array");
        }
        if (verifiableCredentials.isEmpty()) {
            throw new CredentialException("No Verifiable Credential found in Verifiable Presentation");
        }
        // Ensure the first item is a String (JWT in string form)
        Object firstCredential = verifiableCredentials.get(0);
        if (!(firstCredential instanceof String)) {
            throw new CredentialException("The first Verifiable Credential is not a valid JWT string");
        }
        return firstCredential;
    }
}



