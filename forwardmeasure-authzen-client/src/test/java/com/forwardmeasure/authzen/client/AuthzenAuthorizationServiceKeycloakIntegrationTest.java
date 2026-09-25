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
package com.forwardmeasure.authzen.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.forwardmeasure.authzen.Action;
import com.forwardmeasure.authzen.ActiveOrganization;
import com.forwardmeasure.authzen.AuthorizationDecision;
import com.forwardmeasure.authzen.AuthorizationRequest;
import com.forwardmeasure.authzen.AuthorizationResource;
import com.forwardmeasure.authzen.AuthorizationService;
import com.forwardmeasure.authzen.KeycloakOrganizationClaims;
import com.forwardmeasure.authzen.testkit.AuthzenKeycloakFixture;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Real, no-mocks, no-fake-server proof: a real Keycloak 26.7 container (via {@link
 * AuthzenKeycloakFixture}), a real signed JWT minted by it, real Organizations/roles/AuthZEN
 * resources/scopes/policies/permissions provisioned through its own real Admin REST API, and a real
 * {@link AuthzenAuthorizationService} (built through {@link AuthzenAuthorizationFactory}, exactly
 * the way every real consumer constructs one) making real HTTP calls to that same container's real
 * {@code /realms/{realm}/authzen/access/v1/evaluation} endpoint.
 *
 * <p>{@link AuthzenAuthorizationServiceTest} (the sibling in this same package) already proves the
 * HTTP client's own request/response/caching/error-handling logic against a fake in-process server
 * - useful, fast, but it cannot prove this library's actual AuthZEN request shape is something a
 * real Keycloak PDP accepts and evaluates correctly. This test is what proves that: added because
 * "no real integration tests" was a real, correctly-raised blocker to depending on this library
 * anywhere.
 */
class AuthzenAuthorizationServiceKeycloakIntegrationTest {

  private static final String ROLE = "widget-reader";
  private static final String RESOURCE_TYPE = "authzen-test-widget";
  private static final String RESOURCE_ID = "widgets";
  private static final String PERMISSION_NAME = "widget-read-permission";
  private static final Action GRANTED_SCOPE = TestAction.READ;
  private static final Action UNGRANTED_SCOPE = TestAction.DELETE;

  private static final ObjectMapper MAPPER = new ObjectMapper();

  /** A minimal, real {@link Action} implementor - the shape every product's own enum matches. */
  private enum TestAction implements Action {
    READ("widget:read"),
    DELETE("widget:delete");

    private final String scope;

    TestAction(String scope) {
      this.scope = scope;
    }

    @Override
    public String scope() {
      return scope;
    }
  }

  private static AuthzenKeycloakFixture fixture;
  private static AuthorizationService authorization;
  private static ActiveOrganization actor;

  @BeforeAll
  static void startKeycloakAndProvisionRealAuthorization() {
    fixture = AuthzenKeycloakFixture.start();
    UUID tenantId = UUID.randomUUID();
    String organizationId = fixture.provisionTenant("widget-org", tenantId, ROLE);
    fixture.grantResourceAuthorization(
        organizationId,
        RESOURCE_TYPE,
        RESOURCE_ID,
        PERMISSION_NAME,
        ROLE,
        Set.of(GRANTED_SCOPE.scope()));

    String accessToken = fixture.mintUserToken();
    Map<String, Object> claims = decodeClaims(accessToken);
    actor = KeycloakOrganizationClaims.extract(claims, AuthzenKeycloakFixture.CLIENT_ID);

    authorization =
        AuthzenAuthorizationFactory.create(
            MAPPER,
            fixture.issuer(),
            AuthzenKeycloakFixture.AUTHZEN_CLIENT_ID,
            AuthzenKeycloakFixture.AUTHZEN_CLIENT_SECRET,
            Duration.ofSeconds(10),
            Duration.ofSeconds(30),
            100,
            "authzen-integration-test-v1");
  }

  @AfterAll
  static void stopKeycloak() {
    if (fixture != null) {
      fixture.close();
    }
  }

  @Test
  void permitsAnActionARealRoleWasGrantedByARealKeycloakAuthzenEvaluation() {
    AuthorizationDecision decision =
        authorization.evaluate(
            new AuthorizationRequest(
                actor,
                new AuthorizationResource(RESOURCE_TYPE, RESOURCE_ID, Map.of()),
                GRANTED_SCOPE,
                "correlation-permit",
                Map.of()));
    assertTrue(decision.permitted(), "a role holding the granted scope must be permitted");
  }

  @Test
  void deniesAnActionTheRoleWasNeverGrantedByTheSameRealKeycloakAuthzenEvaluation() {
    AuthorizationDecision decision =
        authorization.evaluate(
            new AuthorizationRequest(
                actor,
                new AuthorizationResource(RESOURCE_TYPE, RESOURCE_ID, Map.of()),
                UNGRANTED_SCOPE,
                "correlation-deny",
                Map.of()));
    assertFalse(decision.permitted(), "a scope never granted to this role must be denied");
  }

  @Test
  void requireAuthorizedPassesForAGrantedActionAndThrowsForAnUngrantedOne() {
    authorization.requireAuthorized(
        new AuthorizationRequest(
            actor,
            new AuthorizationResource(RESOURCE_TYPE, RESOURCE_ID, Map.of()),
            GRANTED_SCOPE,
            "correlation-require-permit",
            Map.of()));
    org.junit.jupiter.api.Assertions.assertThrows(
        com.forwardmeasure.authzen.AuthorizationDeniedException.class,
        () ->
            authorization.requireAuthorized(
                new AuthorizationRequest(
                    actor,
                    new AuthorizationResource(RESOURCE_TYPE, RESOURCE_ID, Map.of()),
                    UNGRANTED_SCOPE,
                    "correlation-require-deny",
                    Map.of())));
  }

  @Test
  void theResolvedActorCarriesTheRealProvisionedTenantAndRole() {
    // actorId() is the JWT's own "sub" claim - Keycloak's internal user UUID, not the username -
    // so this only asserts it's genuinely present, not a literal value this test doesn't control.
    assertEquals(Set.of(ROLE), actor.organizationRoles());
    assertFalse(actor.actorId().isBlank());
  }

  private static Map<String, Object> decodeClaims(String jwt) {
    String[] segments = jwt.split("\\.");
    byte[] payload = Base64.getUrlDecoder().decode(segments[1]);
    try {
      return MAPPER.readValue(payload, new TypeReference<Map<String, Object>>() {});
    } catch (java.io.IOException e) {
      throw new java.io.UncheckedIOException(e);
    }
  }
}
