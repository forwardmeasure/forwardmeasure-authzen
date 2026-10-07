/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.forwardmeasure.authzen.testkit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.forwardmeasure.authzen.ActiveOrganization;
import com.forwardmeasure.authzen.KeycloakOrganizationClaims;
import com.forwardmeasure.jpa.tenancy.Did;
import com.forwardmeasure.jpa.tenancy.TenantId;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.testcontainers.containers.Network;

@org.junit.jupiter.api.parallel.ResourceLock("java.net.ProxySelector.default")
class AuthzenFixtureIntegrationTest {
  private static final ObjectMapper JSON = new ObjectMapper();

  @Test
  @Timeout(120)
  void realOrganizationMembershipSeparatesUserReviewerAndWorkerPermissions() throws Exception {
    try (var fixture = AuthzenKeycloakFixture.start();
        var http = HttpClient.newHttpClient()) {
      var did = Did.parse("did:fwmtest:tenant:fixture-contract");
      String role = "reader";
      String org = fixture.provisionTenant("fixture", did, role);
      var user = actor(fixture.mintUserToken());
      assertEquals(TenantId.forDid(did), user.tenantId());
      assertEquals(org, user.organizationId());
      assertEquals(Set.of(role), user.organizationRoles());
      for (int attempt = 0; attempt < 2; attempt++) {
        fixture.grantResourceAuthorization(
            org, "fixture-resource", "population/one", "read-one", role, Set.of("fixture:read"));
        fixture.grantOrganizationClientRole(org, role);
      }
      assertTrue(decision(fixture, http, user, "fixture:read"));
      assertFalse(decision(fixture, http, user, "fixture:delete"));
      var reviewer = actor(fixture.provisionServiceAccountReviewer(org, role));
      assertNotEquals(user.actorId(), reviewer.actorId());
      assertEquals(user.tenantId(), reviewer.tenantId());
      assertTrue(decision(fixture, http, reviewer, "fixture:read"));
      fixture.provisionServiceAccountReviewer(org, role);
      for (int attempt = 0; attempt < 2; attempt++) {
        fixture.createServiceAccountClient("fixture-worker", "local-test-secret");
        fixture.addServiceAccountToOrganization(org, "fixture-worker", "worker");
        fixture.grantOrganizationClientRole(org, "worker");
      }
      var worker = actor(fixture.clientCredentialsToken("fixture-worker", "local-test-secret"));
      assertNotEquals(user.actorId(), worker.actorId());
      assertNotEquals(reviewer.actorId(), worker.actorId());
      assertEquals(user.tenantId(), worker.tenantId());
      assertFalse(decision(fixture, http, worker, "fixture:read"));
      fixture.grantResourceAuthorization(
          org,
          "fixture-resource",
          "population/one",
          "worker-write-one",
          "worker",
          Set.of("fixture:write"));
      assertTrue(decision(fixture, http, worker, "fixture:write"));
      assertFalse(decision(fixture, http, worker, "fixture:read"));
      assertFalse(decision(fixture, http, user, "fixture:write"));
      assertTrue(decision(fixture, http, user, "fixture:read"));
      assertThrows(
          IllegalStateException.class,
          () -> fixture.provisionServiceAccountReviewer(org, "missing-role"));
      assertThrows(
          IllegalStateException.class,
          () -> fixture.addServiceAccountToOrganization(org, "absent-client", "worker"));
      assertThrows(
          IllegalStateException.class,
          () -> fixture.grantOrganizationClientRole("missing-organization", "reader"));
    }
  }

  @Test
  @Timeout(60)
  void networkFixtureUsesContainerIssuerWhileHostAdminAndTokensRemainReachable() throws Exception {
    try (var network = Network.newNetwork();
        var fixture = AuthzenKeycloakFixture.start(network, "fixture-keycloak")) {
      assertEquals(
          "http://fixture-keycloak:8080/realms/" + AuthzenKeycloakFixture.REALM,
          fixture.networkIssuer().toString());
      assertNotEquals(fixture.networkIssuer(), fixture.issuer());
      fixture.provisionTenant("network", Did.parse("did:fwmtest:tenant:network"), "reader");
      var claims = claims(fixture.mintUserToken());
      assertEquals(fixture.networkIssuer().toString(), claims.get("iss"));
      assertEquals(
          Set.of("reader"),
          KeycloakOrganizationClaims.extract(claims, AuthzenKeycloakFixture.CLIENT_ID)
              .organizationRoles());
    }
  }

  @Test
  @Timeout(90)
  void expiredAdministratorTokenRefreshesDuringLongRunningFixtures() throws Exception {
    try (var fixture = AuthzenKeycloakFixture.start();
        var http = HttpClient.newHttpClient()) {
      String admin = administratorToken(fixture, http);
      admin(fixture, http, admin, "PUT", "realms/master", Map.of("accessTokenLifespan", 3), 204);
      String organization =
          fixture.provisionTenant("expiry", Did.parse("did:fwmtest:tenant:expiry"), "reader");
      Thread.sleep(4_000);
      // The fixture's cached token has actually expired on the server. A second admin operation
      // must acquire another token, not reuse the one from tenant provisioning.
      fixture.grantOrganizationClientRole(organization, "reviewer");
      fixture.grantResourceAuthorization(
          organization,
          "fixture-resource",
          "population/one",
          "after-expiry",
          "reader",
          Set.of("fixture:read"));
      assertTrue(decision(fixture, http, actor(fixture.mintUserToken()), "fixture:read"));
    }
  }

  @Test
  @Timeout(90)
  void incompleteRealmImportFailsWithTheMissingIdentityInsteadOfProvisioningPartialAccess()
      throws Exception {
    try (var fixture = AuthzenKeycloakFixture.start();
        var http = HttpClient.newHttpClient()) {
      String admin = administratorToken(fixture, http);
      String realm = "realms/" + AuthzenKeycloakFixture.REALM + "/";
      JsonNode client =
          admin(
                  fixture,
                  http,
                  admin,
                  "GET",
                  realm + "clients?clientId=" + AuthzenKeycloakFixture.CLIENT_ID,
                  null,
                  200)
              .get(0);
      String clientId = client.path("id").asText();
      admin(fixture, http, admin, "DELETE", realm + "clients/" + clientId, null, 204);
      var missingClient =
          assertThrows(
              IllegalStateException.class,
              () ->
                  fixture.provisionTenant(
                      "missing-client", Did.parse("did:fwmtest:tenant:missing-client"), "reader"));
      assertTrue(
          missingClient
              .getMessage()
              .contains("client " + AuthzenKeycloakFixture.CLIENT_ID + " was not found"));
      admin(fixture, http, admin, "POST", realm + "clients", client, 201);
      JsonNode user =
          admin(
                  fixture,
                  http,
                  admin,
                  "GET",
                  realm + "users?username=" + AuthzenKeycloakFixture.USERNAME + "&exact=true",
                  null,
                  200)
              .get(0);
      admin(fixture, http, admin, "DELETE", realm + "users/" + user.path("id").asText(), null, 204);
      var missingUser =
          assertThrows(
              IllegalStateException.class,
              () ->
                  fixture.provisionTenant(
                      "missing-user", Did.parse("did:fwmtest:tenant:missing-user"), "reader"));
      assertTrue(
          missingUser
              .getMessage()
              .contains("test user " + AuthzenKeycloakFixture.USERNAME + " was not found"));
      JsonNode service =
          admin(
                  fixture,
                  http,
                  admin,
                  "GET",
                  realm + "clients?clientId=" + AuthzenKeycloakFixture.AUTHZEN_CLIENT_ID,
                  null,
                  200)
              .get(0);
      admin(
          fixture,
          http,
          admin,
          "DELETE",
          realm + "clients/" + service.path("id").asText(),
          null,
          204);
      var missingResourceServer =
          assertThrows(
              IllegalStateException.class,
              () ->
                  fixture.grantResourceAuthorization(
                      "no-organization",
                      "fixture-resource",
                      "population/one",
                      "missing-server",
                      "reader",
                      Set.of("fixture:read")));
      assertTrue(
          missingResourceServer
              .getMessage()
              .contains("client " + AuthzenKeycloakFixture.AUTHZEN_CLIENT_ID + " was not found"));
    }
  }

  @Test
  @Timeout(60)
  void disabledAdministratorFailsBeforeTenantCreation() throws Exception {
    try (var fixture = AuthzenKeycloakFixture.start();
        var http = HttpClient.newHttpClient()) {
      String token = administratorToken(fixture, http);
      JsonNode administrator =
          admin(
                  fixture,
                  http,
                  token,
                  "GET",
                  "realms/master/users?username=admin&exact=true",
                  null,
                  200)
              .get(0);
      admin(
          fixture,
          http,
          token,
          "PUT",
          "realms/master/users/" + administrator.path("id").asText(),
          Map.of("enabled", false),
          204);
      var failure =
          assertThrows(
              IllegalStateException.class,
              () ->
                  fixture.provisionTenant(
                      "disabled-admin", Did.parse("did:fwmtest:tenant:disabled-admin"), "reader"));
      assertTrue(
          failure.getMessage().matches("(?s).*admin token request returned HTTP (400|401):.*"),
          failure.getMessage());
      assertTrue(
          failure.getMessage().toLowerCase(java.util.Locale.ROOT).contains("disabled"),
          failure.getMessage());
    }
  }

  private static String administratorToken(AuthzenKeycloakFixture fixture, HttpClient http)
      throws Exception {
    var response =
        http.send(
            HttpRequest.newBuilder(
                    fixture.issuer().resolve("/realms/master/protocol/openid-connect/token"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(
                    HttpRequest.BodyPublishers.ofString(
                        "grant_type=password&client_id=admin-cli&username=admin&password=admin-integration-only"))
                .build(),
            HttpResponse.BodyHandlers.ofString());
    assertEquals(200, response.statusCode());
    return JSON.readTree(response.body()).path("access_token").asText();
  }

  private static JsonNode admin(
      AuthzenKeycloakFixture fixture,
      HttpClient http,
      String token,
      String method,
      String path,
      Object payload,
      int status)
      throws Exception {
    var request =
        HttpRequest.newBuilder(fixture.issuer().resolve("/admin/" + path))
            .header("Authorization", "Bearer " + token)
            .header("Content-Type", "application/json")
            .method(
                method,
                payload == null
                    ? HttpRequest.BodyPublishers.noBody()
                    : HttpRequest.BodyPublishers.ofString(JSON.writeValueAsString(payload)))
            .build();
    var response = http.send(request, HttpResponse.BodyHandlers.ofString());
    assertEquals(status, response.statusCode(), "Admin fixture setup " + method + " " + path);
    return response.body().isBlank() ? JSON.createObjectNode() : JSON.readTree(response.body());
  }

  static ActiveOrganization actor(String token) throws Exception {
    return KeycloakOrganizationClaims.extract(claims(token), AuthzenKeycloakFixture.CLIENT_ID);
  }

  private static Map<String, Object> claims(String token) throws Exception {
    return JSON.readValue(
        Base64.getUrlDecoder().decode(token.split("\\.")[1]), new TypeReference<>() {});
  }

  static boolean decision(
      AuthzenKeycloakFixture fixture, HttpClient http, ActiveOrganization actor, String action)
      throws Exception {
    var properties =
        Map.of(
            "organization_id",
            actor.organizationId(),
            "active_organization_id",
            actor.organizationId(),
            "tenant_id",
            actor.tenantId().toString(),
            "organization_roles",
            List.copyOf(actor.organizationRoles()),
            "roles",
            List.copyOf(actor.organizationRoles()));
    var payload =
        Map.of(
            "subject",
            Map.of("type", "user", "id", actor.actorId(), "properties", properties),
            "resource",
            Map.of(
                "type",
                "fixture-resource",
                "id",
                "population/one",
                "properties",
                Map.of("tenant_id", actor.tenantId().toString())),
            "action",
            Map.of("name", action),
            "context",
            Map.of(
                "active_organization_id",
                actor.organizationId(),
                "tenant_id",
                actor.tenantId().toString()));
    var request =
        HttpRequest.newBuilder(URI.create(fixture.issuer() + "/authzen/access/v1/evaluation"))
            .header(
                "Authorization",
                "Bearer "
                    + fixture.clientCredentialsToken(
                        AuthzenKeycloakFixture.AUTHZEN_CLIENT_ID,
                        AuthzenKeycloakFixture.AUTHZEN_CLIENT_SECRET))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(JSON.writeValueAsString(payload)))
            .build();
    var response = http.send(request, HttpResponse.BodyHandlers.ofString());
    assertEquals(200, response.statusCode(), response.body());
    var decision = JSON.readTree(response.body()).path("decision");
    assertTrue(decision.isBoolean());
    return decision.booleanValue();
  }
}
