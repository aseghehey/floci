package io.github.hectorvent.floci.services.kms;

import io.github.hectorvent.floci.testing.RestAssuredJsonUtils;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.ValidatableResponse;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.not;

/**
 * Grants for an AWS service principal (KMS API Reference, CreateGrant): "You can also create a grant
 * for an AWS service principal by specifying the GranteeServicePrincipal parameter." The request
 * names either GranteePrincipal or GranteeServicePrincipal, never both; a GranteeServicePrincipal
 * needs a SourceArn grant constraint and a RetiringPrincipal or RetiringServicePrincipal; and
 * RetiringPrincipal and RetiringServicePrincipal exclude each other. ListGrants returns and filters
 * on GranteeServicePrincipal, and ListRetirableGrants does the same for RetiringServicePrincipal.
 */
@QuarkusTest
class KmsGrantServicePrincipalIntegrationTest {

    private static final String KMS_CONTENT_TYPE = "application/x-amz-json-1.1";
    private static final String SOURCE_ARN = "arn:aws:logs:us-east-1:000000000000:log-group:grants";
    private static final String GRANTEE = "arn:aws:iam::000000000000:user/grantee";

    @BeforeAll
    static void configureRestAssured() {
        RestAssuredJsonUtils.configureAwsContentTypes();
    }

    private static ValidatableResponse kms(String operation, String body) {
        return given()
                .header("X-Amz-Target", "TrentService." + operation)
                .contentType(KMS_CONTENT_TYPE)
                .body(body)
                .when().post("/")
                .then();
    }

    private static String createKey() {
        return kms("CreateKey", "{\"Description\":\"service principal grants\"}")
                .statusCode(200).extract().path("KeyMetadata.KeyId");
    }

    /** A service principal no other test uses, so region-wide listings see only this test's grants. */
    private static String servicePrincipal() {
        return "svc-" + UUID.randomUUID().toString().substring(0, 8) + ".amazonaws.com";
    }

    private static String grantBody(String keyId, String members) {
        return "{\"KeyId\":\"" + keyId + "\",\"Operations\":[\"Encrypt\",\"Decrypt\"]," + members + "}";
    }

    private static String sourceArnConstraint() {
        return "\"Constraints\":{\"SourceArn\":\"" + SOURCE_ARN + "\"}";
    }

    @Test
    void aGrantForAServicePrincipalIsListedWithItsServicePrincipalsAndSourceArn() {
        String keyId = createKey();
        String grantee = servicePrincipal();
        String retiring = servicePrincipal();
        String grantId = kms("CreateGrant", grantBody(keyId, "\"GranteeServicePrincipal\":\"" + grantee
                + "\",\"RetiringServicePrincipal\":\"" + retiring + "\"," + sourceArnConstraint()))
                .statusCode(200).extract().path("GrantId");

        kms("ListGrants", "{\"KeyId\":\"" + keyId + "\"}")
                .statusCode(200)
                .body("Grants.size()", equalTo(1))
                .body("Grants[0].GrantId", equalTo(grantId))
                .body("Grants[0].GranteeServicePrincipal", equalTo(grantee))
                .body("Grants[0].RetiringServicePrincipal", equalTo(retiring))
                .body("Grants[0].Constraints.SourceArn", equalTo(SOURCE_ARN))
                .body("Grants[0]", not(hasKey("GranteePrincipal")))
                .body("Grants[0]", not(hasKey("RetiringPrincipal")));
    }

    @Test
    void listGrantsFiltersOnTheGranteeServicePrincipal() {
        String keyId = createKey();
        String grantee = servicePrincipal();
        String serviceGrant = kms("CreateGrant", grantBody(keyId, "\"GranteeServicePrincipal\":\"" + grantee
                + "\",\"RetiringPrincipal\":\"" + GRANTEE + "\"," + sourceArnConstraint()))
                .statusCode(200).extract().path("GrantId");
        kms("CreateGrant", grantBody(keyId, "\"GranteePrincipal\":\"" + GRANTEE + "\""))
                .statusCode(200);
        kms("CreateGrant", grantBody(keyId, "\"GranteeServicePrincipal\":\"" + servicePrincipal()
                + "\",\"RetiringPrincipal\":\"" + GRANTEE + "\"," + sourceArnConstraint()))
                .statusCode(200);

        kms("ListGrants", "{\"KeyId\":\"" + keyId + "\",\"GranteeServicePrincipal\":\"" + grantee + "\"}")
                .statusCode(200)
                .body("Grants.size()", equalTo(1))
                .body("Grants[0].GrantId", equalTo(serviceGrant))
                .body("Grants[0].RetiringPrincipal", equalTo(GRANTEE));
        kms("ListGrants", "{\"KeyId\":\"" + keyId + "\",\"GranteePrincipal\":\"" + GRANTEE + "\"}")
                .statusCode(200)
                .body("Grants.size()", equalTo(1))
                .body("Grants[0].GranteePrincipal", equalTo(GRANTEE))
                .body("Grants[0]", not(hasKey("GranteeServicePrincipal")));
    }

    @Test
    void listRetirableGrantsFiltersOnTheRetiringServicePrincipal() {
        String keyId = createKey();
        String retiring = servicePrincipal();
        String grantId = kms("CreateGrant", grantBody(keyId, "\"GranteePrincipal\":\"" + GRANTEE
                + "\",\"RetiringServicePrincipal\":\"" + retiring + "\""))
                .statusCode(200).extract().path("GrantId");
        kms("CreateGrant", grantBody(keyId, "\"GranteePrincipal\":\"" + GRANTEE
                + "\",\"RetiringServicePrincipal\":\"" + servicePrincipal() + "\""))
                .statusCode(200);

        kms("ListRetirableGrants", "{\"RetiringServicePrincipal\":\"" + retiring + "\"}")
                .statusCode(200)
                .body("Grants.size()", equalTo(1))
                .body("Grants[0].GrantId", equalTo(grantId))
                .body("Grants[0].RetiringServicePrincipal", equalTo(retiring))
                .body("Grants[0].GranteePrincipal", equalTo(GRANTEE));
    }

    @Test
    void createGrantNamesExactlyOneGrantee() {
        String keyId = createKey();
        kms("CreateGrant", grantBody(keyId, "\"GranteePrincipal\":\"" + GRANTEE
                + "\",\"GranteeServicePrincipal\":\"" + servicePrincipal() + "\",\"RetiringPrincipal\":\""
                + GRANTEE + "\"," + sourceArnConstraint()))
                .statusCode(400).body("__type", equalTo("ValidationException"));
        kms("CreateGrant", grantBody(keyId, "\"RetiringPrincipal\":\"" + GRANTEE + "\"," + sourceArnConstraint()))
                .statusCode(400).body("__type", equalTo("ValidationException"));
    }

    @Test
    void aGranteeServicePrincipalNeedsASourceArnConstraintAndARetiringPrincipal() {
        String keyId = createKey();
        kms("CreateGrant", grantBody(keyId, "\"GranteeServicePrincipal\":\"" + servicePrincipal()
                + "\",\"RetiringPrincipal\":\"" + GRANTEE + "\""))
                .statusCode(400).body("__type", equalTo("ValidationException"));
        kms("CreateGrant", grantBody(keyId, "\"GranteeServicePrincipal\":\"" + servicePrincipal()
                + "\",\"RetiringPrincipal\":\"" + GRANTEE + "\","
                + "\"Constraints\":{\"EncryptionContextSubset\":{\"purpose\":\"test\"}}"))
                .statusCode(400).body("__type", equalTo("ValidationException"));
        kms("CreateGrant", grantBody(keyId, "\"GranteeServicePrincipal\":\"" + servicePrincipal() + "\","
                + sourceArnConstraint()))
                .statusCode(400).body("__type", equalTo("ValidationException"));
    }

    @Test
    void retiringPrincipalAndRetiringServicePrincipalExcludeEachOther() {
        String keyId = createKey();
        kms("CreateGrant", grantBody(keyId, "\"GranteePrincipal\":\"" + GRANTEE + "\",\"RetiringPrincipal\":\""
                + GRANTEE + "\",\"RetiringServicePrincipal\":\"" + servicePrincipal() + "\""))
                .statusCode(400).body("__type", equalTo("ValidationException"));
    }

    @Test
    void servicePrincipalsFollowTheModeledLengthAndPattern() {
        String keyId = createKey();
        String tooLong = "a".repeat(115) + ".amazonaws.com";
        for (String invalid : new String[] {"", "amazonaws", "svc.amazonaws.com/", tooLong}) {
            kms("CreateGrant", grantBody(keyId, "\"GranteeServicePrincipal\":\"" + invalid
                    + "\",\"RetiringPrincipal\":\"" + GRANTEE + "\"," + sourceArnConstraint()))
                    .statusCode(400).body("__type", equalTo("ValidationException"));
            kms("CreateGrant", grantBody(keyId, "\"GranteePrincipal\":\"" + GRANTEE
                    + "\",\"RetiringServicePrincipal\":\"" + invalid + "\""))
                    .statusCode(400).body("__type", equalTo("ValidationException"));
            kms("ListGrants", "{\"KeyId\":\"" + keyId + "\",\"GranteeServicePrincipal\":\"" + invalid + "\"}")
                    .statusCode(400).body("__type", equalTo("ValidationException"));
            kms("ListRetirableGrants", "{\"RetiringServicePrincipal\":\"" + invalid + "\"}")
                    .statusCode(400).body("__type", equalTo("ValidationException"));
        }
        String longest = "a".repeat(114) + ".amazonaws.com";
        kms("CreateGrant", grantBody(keyId, "\"GranteeServicePrincipal\":\"" + longest
                + "\",\"RetiringPrincipal\":\"" + GRANTEE + "\"," + sourceArnConstraint()))
                .statusCode(200);
    }

    @Test
    void theListFiltersNameOnePrincipalKind() {
        String keyId = createKey();
        kms("ListGrants", "{\"KeyId\":\"" + keyId + "\",\"GranteePrincipal\":\"" + GRANTEE
                + "\",\"GranteeServicePrincipal\":\"" + servicePrincipal() + "\"}")
                .statusCode(400).body("__type", equalTo("ValidationException"));
        kms("ListRetirableGrants", "{\"RetiringPrincipal\":\"" + GRANTEE
                + "\",\"RetiringServicePrincipal\":\"" + servicePrincipal() + "\"}")
                .statusCode(400).body("__type", equalTo("ValidationException"));
        kms("ListRetirableGrants", "{}")
                .statusCode(400).body("__type", equalTo("ValidationException"));
    }
}
