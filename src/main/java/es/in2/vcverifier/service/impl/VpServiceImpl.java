package es.in2.vcverifier.service.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.exception.*;
import es.in2.vcverifier.model.credentials.VerifiableCredential;
import es.in2.vcverifier.model.credentials.lear.employee.LEARCredentialEmployee;
import es.in2.vcverifier.model.credentials.lear.machine.LEARCredentialMachine;
import es.in2.vcverifier.model.enums.KeyType;
import es.in2.vcverifier.model.enums.LEARCredentialType;
import es.in2.vcverifier.model.issuer.IssuerCredentialsCapabilities;
import es.in2.vcverifier.service.DIDService;
import es.in2.vcverifier.service.JWTService;
import es.in2.vcverifier.service.TrustFrameworkService;
import es.in2.vcverifier.service.VpService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.json.JSONObject;
import org.springframework.stereotype.Service;

import java.security.PublicKey;
import java.text.ParseException;
import java.util.LinkedHashMap;
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


    @Override
    public boolean validateVerifiablePresentation(String verifiablePresentation) {
        try {
            // Step 1: Extract the Verifiable Credential (VC) from the VP (JWT)
            SignedJWT jwtCredential = extractFirstVerifiableCredential(verifiablePresentation);
            Payload payload = jwtService.getPayloadFromSignedJWT(jwtCredential);

            // Step 2: Map the Payload to the Correct VC Class
            VerifiableCredential verifiableCredential = mapPayloadToVerifiableCredential(payload);


            // Step 2: Validate the issuer
            String credentialIssuerDid = verifiableCredential.getIssuer();

            // Step 3: Extract and validate credential types
            List<String> credentialTypes = verifiableCredential.getType();

            // Step 4: Retrieve the list of issuer capabilities
            List<IssuerCredentialsCapabilities> issuerCapabilitiesList = trustFrameworkService.getTrustedIssuerListData(credentialIssuerDid);

            // Step 5: Validate credential type against issuer capabilities
            validateCredentialTypeWithIssuerCapabilities(issuerCapabilitiesList, credentialTypes);
            log.info("Issuer DID {} is a trusted participant", credentialIssuerDid);

            // Step 5: Extract the mandateId from the Verifiable Credential
            String mandatorOrganizationIdentifier = extractMandatorOrganizationIdentifier(verifiableCredential);

            //TODO this must be validated against the participants list, not the issuer list

            // Validate the mandatee ID with trusted issuer service, if is not present the trustedIssuerListService throws an exception
            trustFrameworkService.getTrustedIssuerListData(DID_ELSI_PREFIX + mandatorOrganizationIdentifier);

            log.info("Mandator OrganizationIdentifier {} is valid and allowed", mandatorOrganizationIdentifier);

            // Step 6: Validate the VP's signature with the DIDService (the DID of the holder of the VP)
            String mandateeId = extractMandateeId(verifiableCredential);
            PublicKey holderPublicKey = didService.getPublicKeyFromDid(mandateeId); // Get the holder's public key in bytes
            jwtService.verifyJWTSignature(verifiablePresentation, holderPublicKey, KeyType.EC); // Validate the VP was signed by the holder DID

            return true; // All validations passed
        } catch (Exception e) {
            log.error("Error during VP validation: {}", e.getMessage());
            return false;
        }
    }

    private VerifiableCredential mapPayloadToVerifiableCredential(Payload payload) {
        Object vcObject = jwtService.getVCFromPayload(payload);
        try {
            Map<String, Object> vcMap = validateAndCastToMap(vcObject);
            List<String> types = extractAndValidateTypes(vcMap);
            return mapToSpecificCredential(vcMap, types);
        } catch (IllegalArgumentException e) {
            throw new CredentialMappingException("Error mapping VC payload to specific Verifiable Credential class: " + e.getMessage());
        }
    }

    private Map<String, Object> validateAndCastToMap(Object vcObject) {
        if (!(vcObject instanceof Map<?, ?> map)) {
            throw new CredentialMappingException("Invalid payload format for Verifiable Credential.");
        }

        // Ensure the map's keys are all types are Strings and values are Objects
        Map<String, Object> validatedMap = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            if (!(entry.getKey() instanceof String)) {
                throw new CredentialMappingException("Invalid key type found in Verifiable Credential map: " + entry.getKey());
            }
            validatedMap.put((String) entry.getKey(), entry.getValue());
        }

        return validatedMap;
    }


    private List<String> extractAndValidateTypes(Map<String, Object> vcMap) {
        Object typeObject = vcMap.get("type");

        // Validate that the "type" object is a list
        if (!(typeObject instanceof List<?> typeList)) {
            throw new CredentialMappingException("'type' key is not a list.");
        }

        // Ensure that all elements in the list are Strings
        if (!typeList.stream().allMatch(String.class::isInstance)) {
            throw new CredentialMappingException("'type' list contains non-string elements.");
        }

        // Safely cast the List<?> to List<String>
        return typeList.stream()
                .map(String.class::cast)
                .toList();
    }

    private VerifiableCredential mapToSpecificCredential(Map<String, Object> vcMap, List<String> types) {
        if (types.contains(LEARCredentialType.LEAR_CREDENTIAL_EMPLOYEE.getValue())) {
            return objectMapper.convertValue(vcMap, LEARCredentialEmployee.class);
        } else if (types.contains(LEARCredentialType.LEAR_CREDENTIAL_MACHINE.getValue())) {
            return objectMapper.convertValue(vcMap, LEARCredentialMachine.class);
        } else {
            throw new InvalidCredentialTypeException("Unsupported credential type: " + types);
        }
    }



    @Override
    public Object getCredentialFromTheVerifiablePresentation(String verifiablePresentation) {
        // Step 1: Extract the Verifiable Credential (VC) from the VP (JWT)
        SignedJWT jwtCredential = extractFirstVerifiableCredential(verifiablePresentation);
        Payload payload = jwtService.getPayloadFromSignedJWT(jwtCredential);
        return jwtService.getVCFromPayload(payload);
    }

    @Override
    public JsonNode getCredentialFromTheVerifiablePresentationAsJsonNode(String verifiablePresentation) {
        return convertObjectToJSONNode(getCredentialFromTheVerifiablePresentation(verifiablePresentation));
    }

    private String extractMandateeId(VerifiableCredential verifiableCredential) {
        if (verifiableCredential instanceof LEARCredentialEmployee employeeCredential) {
            // Obtain the specific CredentialSubject and access the Mandatee information
            LEARCredentialEmployee.CredentialSubject credentialSubject = employeeCredential.getLearCredentialSubject();
            return credentialSubject.mandate().mandatee().id();
        } else if (verifiableCredential instanceof LEARCredentialMachine machineCredential) {
            // Obtain the specific CredentialSubject and access the Mandatee information
            LEARCredentialMachine.CredentialSubject credentialSubject = machineCredential.getLearMachineSubject();
            return credentialSubject.mandate().mandatee().id();
        } else {
            throw new InvalidCredentialTypeException("Invalid Credential Type. LEARCredentialEmployee or LEARCredentialMachine required.");
        }
    }

    private String extractMandatorOrganizationIdentifier(VerifiableCredential verifiableCredential) {
        if (verifiableCredential instanceof LEARCredentialEmployee employeeCredential) {
            // Obtain the specific CredentialSubject and access the Mandator information
            LEARCredentialEmployee.CredentialSubject credentialSubject = employeeCredential.getLearCredentialSubject();
            return credentialSubject.mandate().mandator().organizationIdentifier();
        } else if (verifiableCredential instanceof LEARCredentialMachine machineCredential) {
            // Obtain the specific CredentialSubject and access the Mandator information
            LEARCredentialMachine.CredentialSubject credentialSubject = machineCredential.getLearMachineSubject();
            return credentialSubject.mandate().mandator().organizationIdentifier();
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



