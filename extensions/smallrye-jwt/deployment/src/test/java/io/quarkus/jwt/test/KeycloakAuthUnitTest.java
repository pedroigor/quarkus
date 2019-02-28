package io.quarkus.jwt.test;

import java.io.StringReader;
import java.net.HttpURLConnection;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;

import org.eclipse.microprofile.jwt.Claims;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.ClientScopeRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.ProtocolMapperRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.RolesRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.util.JsonSerialization;

import io.quarkus.test.QuarkusUnitTest;
import io.restassured.RestAssured;
import io.restassured.response.Response;

public class KeycloakAuthUnitTest {
    private static Class[] testClasses = {
            JsonValuejectionEndpoint.class
    };

    private static final String KEYCLOAK_SERVER_HOST = "localhost";
    private static final int KEYCLOAK_SERVER_PORT = 8180;
    private static final String KEYCLOAK_REALM = "protean";

    /**
     * The test generated JWT token string
     */
    private String token;
    // Time claims in the token
    private int iatClaim;
    private int authTimeClaim;
    private int expClaim;

    @RegisterExtension
    static final QuarkusUnitTest config = new QuarkusUnitTest()
            .setArchiveProducer(() -> ShrinkWrap.create(JavaArchive.class)
                    .addClasses(testClasses)
                    .addAsManifestResource("microprofile-config.properties"));

    @BeforeEach
    public void generateToken() throws Exception {
        RealmRepresentation realm = createRealm("protean");

        realm.getUsers().add(createUser("alice", "user", "Tester"));

        RestAssured
                .given()
                .auth().oauth2(getAdminAccessToken())
                .contentType("application/json")
                .body(JsonSerialization.writeValueAsBytes(realm))
                .when()
                .post("http://" + KEYCLOAK_SERVER_HOST + ":" + KEYCLOAK_SERVER_PORT + "/auth/admin/realms").then()
                .statusCode(201);

        token = getAccessToken("alice");
    }

    @AfterEach
    public void removeKeycloakRealm() {
        RestAssured
                .given()
                .auth().oauth2(getAdminAccessToken())
                .when()
                .delete("http://localhost:8180/auth/admin/realms/" + KEYCLOAK_REALM).then().statusCode(204);
    }

    // Basic @ServletSecurity tests
    @Test()
    public void testSecureAccessFailure() {
        RestAssured.when().get("/endp/verifyInjectedIssuer").then()
                .statusCode(401);
    }

    /**
     * Verify that the injected token issuer claim is as expected
     * 
     * @throws Exception
     */
    @Test()
    public void verifyIssuerClaim() throws Exception {
        Response response = RestAssured.given().auth()
                .oauth2(token)
                .when()
                .queryParam(Claims.iss.name(), "http://localhost:8180/auth/realms/protean")
                .queryParam(Claims.auth_time.name(), authTimeClaim)
                .get("/endp/verifyInjectedIssuer").andReturn();

        Assertions.assertEquals(HttpURLConnection.HTTP_OK, response.getStatusCode());
        String replyString = response.body().asString();
        JsonReader jsonReader = Json.createReader(new StringReader(replyString));
        JsonObject reply = jsonReader.readObject();
        Assertions.assertTrue(reply.getBoolean("pass"), reply.getString("msg"));
    }

    private String getAccessToken(String userName) {
        return RestAssured
                .given()
                .param("grant_type", "password")
                .param("username", userName)
                .param("password", userName)
                .param("client_id", "protean-app")
                .param("client_secret", "secret")
                .param("scope", "profile mp-jwt")
                .when()
                .post("http://" + KEYCLOAK_SERVER_HOST + ":" + KEYCLOAK_SERVER_PORT + "/auth/realms/" + KEYCLOAK_REALM
                        + "/protocol/openid-connect/token")
                .as(AccessTokenResponse.class).getToken();
    }

    private static String getAdminAccessToken() {
        return RestAssured
                .given()
                .param("grant_type", "password")
                .param("username", "admin")
                .param("password", "admin")
                .param("client_id", "admin-cli")
                .when()
                .post("http://" + KEYCLOAK_SERVER_HOST + ":" + KEYCLOAK_SERVER_PORT
                        + "/auth/realms/master/protocol/openid-connect/token")
                .as(AccessTokenResponse.class).getToken();
    }

    private static RealmRepresentation createRealm(String name) {
        RealmRepresentation realm = new RealmRepresentation();

        realm.setRealm(KEYCLOAK_REALM);
        realm.setEnabled(true);
        realm.setUsers(new ArrayList<>());
        realm.setClientScopes(new ArrayList<>());
        realm.setDefaultDefaultClientScopes(new ArrayList<>());
        realm.setClients(new ArrayList<>());

        RolesRepresentation roles = new RolesRepresentation();
        List<RoleRepresentation> realmRoles = new ArrayList<>();

        roles.setRealm(realmRoles);
        realm.setRoles(roles);

        realm.getRoles().getRealm().add(new RoleRepresentation("user", null, false));
        realm.getRoles().getRealm().add(new RoleRepresentation("Tester", null, false));

        ClientScopeRepresentation mpwJwtScope = createMpJwtClientScope();
        realm.getClientScopes().add(mpwJwtScope);
        realm.getDefaultDefaultClientScopes().add(mpwJwtScope.getName());

        realm.getClients().add(createClient("protean-app"));

        return realm;
    }

    private static ClientScopeRepresentation createMpJwtClientScope() {
        ClientScopeRepresentation mpwJwtScope = new ClientScopeRepresentation();

        mpwJwtScope.setId("mp-jwt");
        mpwJwtScope.setName("mp-jwt");
        mpwJwtScope.setProtocol("openid-connect");
        mpwJwtScope.setProtocolMappers(new ArrayList<>());

        ProtocolMapperRepresentation roleMapper = new ProtocolMapperRepresentation();

        roleMapper.setProtocolMapper("oidc-usermodel-realm-role-mapper");
        roleMapper.setName("mp-jwt");
        roleMapper.setProtocol("openid-connect");
        Map<String, String> config = new HashMap<>();

        config.put("claim.name", "groups");
        config.put("jsonType.label", "String");
        config.put("access.token.claim", "true");
        config.put("multivalued", "true");
        roleMapper.setConfig(config);

        mpwJwtScope.getProtocolMappers().add(roleMapper);
        return mpwJwtScope;
    }

    private static ClientRepresentation createClient(String clientId) {
        ClientRepresentation client = new ClientRepresentation();

        client.setClientId(clientId);
        client.setPublicClient(false);
        client.setSecret("secret");
        client.setDirectAccessGrantsEnabled(true);
        client.setEnabled(true);
        client.setFullScopeAllowed(true);

        return client;
    }

    private static UserRepresentation createUser(String username, String... realmRoles) {
        UserRepresentation user = new UserRepresentation();

        user.setUsername(username);
        user.setEnabled(true);
        user.setCredentials(new ArrayList<>());
        user.setRealmRoles(Arrays.asList(realmRoles));

        CredentialRepresentation credential = new CredentialRepresentation();

        credential.setType(CredentialRepresentation.PASSWORD);
        credential.setValue(username);
        credential.setTemporary(false);

        user.getCredentials().add(credential);

        return user;
    }
}
