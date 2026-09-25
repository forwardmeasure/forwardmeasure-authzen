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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.forwardmeasure.testcontainers.keycloak.KeycloakTestContainer;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A real, running Keycloak fixture with the Organizations feature genuinely wired for the {@code
 * organization} claim shape {@code KeycloakOrganizationClaims.extract()} expects, plus real
 * Keycloak Authorization Services resources/scopes/policies/permissions for genuine AuthZEN PDP
 * evaluation - not a stub, not a hand-built claims map or a fake HTTP server standing in for
 * Keycloak. Generalized from forwardmeasure-openworkflow's own real {@code
 * KeycloakOrganizationFixture} (which stays there, product-specific to its own Human Task
 * resource): this version's resource/scope/permission provisioning is fully parameterized, so any
 * product - or this shared library's own real integration test - can grant an arbitrary {@code
 * (resourceType, resourceId)} pair whatever action scopes a role needs, the same real Admin REST
 * sequence either way.
 *
 * <p>Uses the same real, already-proven Admin REST call sequence confirmed live against Keycloak
 * 26.7.2 in forwardmeasure-platform's own bootstrap-admin.sh (the origin this whole fixture family
 * traces back to), then mints a real signed JWT for a real user who is really a member of the
 * provisioned Organization.
 */
public final class AuthzenKeycloakFixture implements AutoCloseable {

  public static final String REALM = "authzen-test";
  public static final String CLIENT_ID = "authzen-test-client";
  public static final String USERNAME = "authzen-test-user";
  public static final String PASSWORD = "authzen-test-password";

  /**
   * A second, confidential client dedicated to real Keycloak 26.7 AuthZEN evaluation calls (the
   * experimental {@code /realms/{realm}/authzen/access/v1/evaluation} endpoint, enabled by {@link
   * KeycloakTestContainer}'s own {@code --features=authzen} startup flag). Separate from {@link
   * #CLIENT_ID} the same way a real deployment separates its user-facing OIDC client from its own
   * outbound AuthZEN client-credentials identity.
   */
  public static final String AUTHZEN_CLIENT_ID = "authzen-test-service";

  public static final String AUTHZEN_CLIENT_SECRET = "authzen-test-secret";

  private static final String REALM_RESOURCE = "/authzen-test-realm.json";
  private static final Pattern ACCESS_TOKEN =
      Pattern.compile("\"access_token\"\\s*:\\s*\"([^\"]+)\"");
  private static final Pattern EXPIRES_IN = Pattern.compile("\"expires_in\"\\s*:\\s*(\\d+)");
  // Real, confirmed live 2026-09-23: this fixture's own cached admin token had no expiry tracking
  // at all - a real, later call (this fixture is used by fixtures that boot several minutes' worth
  // of other real services, e.g. RealFowfWorkflowFixture, before ever needing a second admin call)
  // hit Keycloak's own default master-realm access-token TTL, producing a plain 401 on an otherwise
  // correct request. Refresh a safety margin before the real expiry, not exactly at it.
  private static final Duration TOKEN_REFRESH_SAFETY_MARGIN = Duration.ofSeconds(15);

  private final KeycloakTestContainer container;
  private final HttpClient http =
      HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(30)).build();
  private final ObjectMapper mapper = new ObjectMapper();
  private volatile String adminToken;
  private volatile long adminTokenExpiresAtNanos;
  private volatile String clientUuid;
  private volatile String authzenClientUuid;

  private AuthzenKeycloakFixture(KeycloakTestContainer container) {
    this.container = container;
  }

  public static AuthzenKeycloakFixture start() {
    KeycloakTestContainer container = new KeycloakTestContainer(REALM, realmJson()).start();
    return new AuthzenKeycloakFixture(container);
  }

  public URI issuer() {
    return container.issuer();
  }

  /**
   * Provisions one Organization (with the {@code forwardmeasure.tenant-id} attribute {@code
   * KeycloakOrganizationClaims} reads), one client role on {@value #CLIENT_ID}, one Organization
   * Group mapping that role, and adds {@value #USERNAME} as a member of both the Organization and
   * the group. Uses the real, dedicated Organization Groups API ({@code
   * organizations/{orgId}/groups/...}), not a plain realm Group.
   */
  public String provisionTenant(String organizationAlias, UUID tenantId, String roleName) {
    ensureClientRole(roleName);
    String organizationId = createOrganization(organizationAlias, tenantId);
    String groupId = createOrganizationGroup(organizationId, roleName);
    mapRoleOntoOrganizationGroup(organizationId, groupId, roleName);
    String userId = requireUserId();
    addOrganizationMember(organizationId, userId);
    addOrganizationGroupMember(organizationId, groupId, userId);
    return organizationId;
  }

  public String mintUserToken() {
    return container.passwordToken(CLIENT_ID, USERNAME, PASSWORD);
  }

  /**
   * Adds {@value #AUTHZEN_CLIENT_ID}'s own real Keycloak service-account user (confidential clients
   * with {@code serviceAccountsEnabled: true}, which this fixture's own realm already declares for
   * that client, each get one) to {@code organizationId}'s Organization and the given role's own
   * Group - mirrors {@link #provisionTenant}'s identical member/group-membership calls, resolving a
   * different identity's own Keycloak user id instead of {@link #USERNAME}'s.
   *
   * <p>Real reason this exists, not a hypothetical: {@code
   * WorkflowGovernanceServiceImpl#publishWorkflowDefinition} unconditionally requires the actor who
   * publishes a definition to be a genuinely different identity than whoever authored it (a real
   * maker-checker rule, confirmed by direct source read) - {@link #mintUserToken()} only ever mints
   * for the one fixed {@link #USERNAME}, so a caller proving that governance flow for real needs a
   * second, independently-authenticatable identity in the same Organization. Mirrors
   * forwardmeasure-entity-intelligence's own real, already-proven {@code
   * WorkflowDefinitionPublisherMain}, which authenticates its own "author" and "reviewer" calls as
   * two distinct client-credentials identities for exactly this reason.
   *
   * @return the client-credentials bearer token for {@value #AUTHZEN_CLIENT_ID}'s own
   *     service-account user, now provisioned as a real member of {@code organizationId} holding
   *     {@code roleName} - ready to use as a genuinely different actor from {@link
   *     #mintUserToken()}.
   */
  public String provisionServiceAccountReviewer(String organizationId, String roleName) {
    // Requires provisionTenant to have already been called for (organizationId, roleName) - this
    // method only adds a second member to the group/role-mapping that call already created, it
    // does not create either from scratch (findOrganizationGroupId throws if that group is
    // missing).
    String groupId = findOrganizationGroupId(organizationId, roleName);
    String serviceAccountUserId = serviceAccountUserId();
    send(
        "POST",
        adminBase().resolve("organizations/" + organizationId + "/members"),
        serviceAccountUserId,
        201,
        204,
        409);
    send(
        "PUT",
        adminBase()
            .resolve(
                "organizations/"
                    + organizationId
                    + "/groups/"
                    + groupId
                    + "/members/"
                    + serviceAccountUserId),
        null,
        204,
        409);
    return container.clientCredentialsToken(AUTHZEN_CLIENT_ID, AUTHZEN_CLIENT_SECRET);
  }

  private String serviceAccountUserId() {
    return requiredText(
        send(
                "GET",
                adminBase().resolve("clients/" + authzenClientUuid() + "/service-account-user"),
                null,
                200)
            .body(),
        "id");
  }

  /**
   * Provisions everything a real Keycloak 26.7 AuthZEN evaluation needs to permit {@code
   * roleName}-holding actors to perform each of {@code actionScopes} against one resource
   * identified by {@code (resourceType, resourceId)} - a genuinely generic version of the origin
   * fixture's own {@code grantHumanTaskAuthorization}, parameterized instead of hardcoded to one
   * product's own resource shape. Idempotent: safe to call once per distinct {@code (resourceId,
   * roleName)} pair (typically once per fixture, not once per tenant, since Keycloak Authorization
   * Services resources/scopes/policies/permissions are realm/client-scoped, not
   * Organization-scoped).
   *
   * <p>{@code organizationId} must be the value {@link #provisionTenant} returned for a call with
   * this same {@code roleName} - this method maps the role onto that Organization's own Group
   * (already created by {@code provisionTenant}) rather than assuming any particular call order, so
   * {@code provisionTenant} must run first.
   *
   * <p>Uses the {@code organization-role} custom Keycloak Policy Provider (see {@code
   * OrganizationRolePolicyProvider} in {@code helm-charts/charts/keycloak-helm-chart/
   * policy-provider}), not a native Role or Group policy - confirmed live that neither native
   * policy type can recognize a role granted only via Organization-Group membership (Keycloak's own
   * admin API explicitly rejects a Group-type policy referencing an Organization group; a Role-type
   * policy only ever sees a role granted directly to the identity, Organization membership or not).
   * {@code roleName} is therefore never granted directly to the test user or the AuthZEN service
   * account here - a direct grant would satisfy a native Role policy regardless of Organization
   * membership, silently masking the exact gap this fixture exists to catch. The role instead lives
   * on {@value #AUTHZEN_CLIENT_ID} (the AuthZEN evaluation's real resource-server client - {@code
   * OrganizationRolePolicyProvider} resolves the role via {@code resourceServer.getClientId()}, not
   * {@value #CLIENT_ID}) and is mapped onto {@code organizationId}'s own Organization Group of the
   * same name - the real path {@code OrganizationRolePolicyProvider} walks via {@code
   * OrganizationProvider .getOrganizationGroupsByMember}.
   */
  public void grantResourceAuthorization(
      String organizationId,
      String resourceType,
      String resourceId,
      String permissionName,
      String roleName,
      Set<String> actionScopes) {
    ensureAuthzenClientRole(roleName);
    mapAuthzenRoleOntoOrganizationGroup(organizationId, roleName);
    for (String scope : actionScopes) {
      ensureAuthzenScope(scope);
    }
    String keycloakResourceId = ensureResource(resourceType, resourceId, actionScopes);
    String policyId = ensureOrganizationRolePolicy(roleName);
    ensureScopePermission(permissionName, keycloakResourceId, actionScopes, policyId);
  }

  private void ensureAuthzenClientRole(String roleName) {
    Response existing =
        send(
            "GET",
            adminBase().resolve("clients/" + authzenClientUuid() + "/roles/" + roleName),
            null,
            200,
            404);
    if (existing.status() == 404) {
      send(
          "POST",
          adminBase().resolve("clients/" + authzenClientUuid() + "/roles"),
          Map.of("name", roleName),
          201,
          204,
          409);
    }
  }

  private void mapAuthzenRoleOntoOrganizationGroup(String organizationId, String roleName) {
    String groupId = findOrganizationGroupId(organizationId, roleName);
    JsonNode role =
        send(
                "GET",
                adminBase().resolve("clients/" + authzenClientUuid() + "/roles/" + roleName),
                null,
                200)
            .body();
    send(
        "POST",
        adminBase()
            .resolve(
                "organizations/"
                    + organizationId
                    + "/groups/"
                    + groupId
                    + "/role-mappings/clients/"
                    + authzenClientUuid()),
        List.of(role),
        201,
        204,
        409);
  }

  private String findOrganizationGroupId(String organizationId, String groupName) {
    JsonNode groups =
        send("GET", adminBase().resolve("organizations/" + organizationId + "/groups"), null, 200)
            .body();
    for (JsonNode group : groups) {
      if (groupName.equals(group.path("name").asText())) {
        return requiredText(group, "id");
      }
    }
    throw new IllegalStateException(
        "Organization "
            + organizationId
            + " has no group named "
            + groupName
            + " - call provisionTenant with a matching roleName before grantResourceAuthorization");
  }

  private String ensureOrganizationRolePolicy(String roleName) {
    String policyName = "authzen-test-" + roleName + "-organization-role-policy";
    send(
        "POST",
        adminBase()
            .resolve(
                "clients/"
                    + authzenClientUuid()
                    + "/authz/resource-server/policy/organization-role"),
        Map.of("name", policyName, "logic", "POSITIVE", "config", Map.of("role", roleName)),
        201,
        204,
        409);
    JsonNode policies =
        send(
                "GET",
                URI.create(
                    adminBase()
                            .resolve(
                                "clients/" + authzenClientUuid() + "/authz/resource-server/policy")
                            .toString()
                        + "?name="
                        + URLEncoder.encode(policyName, StandardCharsets.UTF_8)),
                null,
                200)
            .body();
    for (JsonNode policy : policies) {
      if (policyName.equals(policy.path("name").asText())) {
        return requiredText(policy, "id");
      }
    }
    throw new IllegalStateException(
        "Keycloak did not return the created organization-role policy " + policyName);
  }

  private void ensureAuthzenScope(String scopeName) {
    send(
        "POST",
        adminBase().resolve("clients/" + authzenClientUuid() + "/authz/resource-server/scope"),
        Map.of("name", scopeName),
        201,
        204,
        409);
  }

  private String authzenScopeId(String scopeName) {
    JsonNode scopes =
        send(
                "GET",
                adminBase()
                    .resolve("clients/" + authzenClientUuid() + "/authz/resource-server/scope"),
                null,
                200)
            .body();
    for (JsonNode scope : scopes) {
      if (scopeName.equals(scope.path("name").asText())) {
        return requiredText(scope, "id");
      }
    }
    throw new IllegalStateException(
        "Keycloak did not return the created AuthZEN scope " + scopeName);
  }

  /** Creates (or updates the scope set of) the resource; returns its own Keycloak-assigned id. */
  private String ensureResource(String resourceType, String resourceId, Set<String> actionScopes) {
    List<Map<String, String>> scopeRefs =
        actionScopes.stream().map(scope -> Map.of("name", scope)).toList();
    send(
        "POST",
        adminBase().resolve("clients/" + authzenClientUuid() + "/authz/resource-server/resource"),
        Map.of(
            "name", resourceId,
            "type", resourceType,
            "scopes", scopeRefs,
            "ownerManagedAccess", false),
        201,
        204,
        409);
    JsonNode resources =
        send(
                "GET",
                URI.create(
                    adminBase()
                            .resolve(
                                "clients/"
                                    + authzenClientUuid()
                                    + "/authz/resource-server/resource")
                            .toString()
                        + "?name="
                        + URLEncoder.encode(resourceId, StandardCharsets.UTF_8)
                        + "&exactName=true"),
                null,
                200)
            .body();
    for (JsonNode resource : resources) {
      if (resourceId.equals(resource.path("name").asText())) {
        return requiredText(resource, "_id");
      }
    }
    throw new IllegalStateException("Keycloak did not return the created resource " + resourceId);
  }

  private void ensureScopePermission(
      String permissionName, String resourceId, Set<String> actionScopes, String policyId) {
    List<String> scopeIds = actionScopes.stream().map(this::authzenScopeId).toList();
    send(
        "POST",
        adminBase()
            .resolve("clients/" + authzenClientUuid() + "/authz/resource-server/permission/scope"),
        Map.of(
            "name",
            permissionName,
            "resources",
            List.of(resourceId),
            "scopes",
            scopeIds,
            "policies",
            List.of(policyId),
            "decisionStrategy",
            "AFFIRMATIVE"),
        201,
        204,
        409);
  }

  @Override
  public void close() {
    container.close();
  }

  private void ensureClientRole(String roleName) {
    Response existing =
        send(
            "GET",
            adminBase().resolve("clients/" + clientUuid() + "/roles/" + roleName),
            null,
            200,
            404);
    if (existing.status() == 404) {
      send(
          "POST",
          adminBase().resolve("clients/" + clientUuid() + "/roles"),
          Map.of("name", roleName),
          201,
          204,
          409);
    }
  }

  private String createOrganization(String alias, UUID tenantId) {
    Response created =
        send(
            "POST",
            adminBase().resolve("organizations"),
            Map.of(
                "name",
                alias,
                "alias",
                alias,
                "enabled",
                true,
                "attributes",
                Map.of("forwardmeasure.tenant-id", List.of(tenantId.toString()))),
            201);
    return created
        .location()
        .map(AuthzenKeycloakFixture::lastPathSegment)
        .orElseThrow(
            () ->
                new IllegalStateException(
                    "Keycloak did not return the created Organization location"));
  }

  private String createOrganizationGroup(String organizationId, String groupName) {
    send(
        "POST",
        adminBase().resolve("organizations/" + organizationId + "/groups"),
        Map.of("name", groupName),
        201,
        204,
        409);
    JsonNode groups =
        send("GET", adminBase().resolve("organizations/" + organizationId + "/groups"), null, 200)
            .body();
    for (JsonNode group : groups) {
      if (groupName.equals(group.path("name").asText())) {
        return requiredText(group, "id");
      }
    }
    throw new IllegalStateException(
        "Keycloak did not return the created Organization Group " + groupName);
  }

  private void mapRoleOntoOrganizationGroup(
      String organizationId, String groupId, String roleName) {
    JsonNode role =
        send(
                "GET",
                adminBase().resolve("clients/" + clientUuid() + "/roles/" + roleName),
                null,
                200)
            .body();
    send(
        "POST",
        adminBase()
            .resolve(
                "organizations/"
                    + organizationId
                    + "/groups/"
                    + groupId
                    + "/role-mappings/clients/"
                    + clientUuid()),
        List.of(role),
        201,
        204,
        409);
  }

  private String requireUserId() {
    String query = URLEncoder.encode(USERNAME, StandardCharsets.UTF_8);
    JsonNode users =
        send(
                "GET",
                URI.create(
                    adminBase().resolve("users").toString() + "?username=" + query + "&exact=true"),
                null,
                200)
            .body();
    for (JsonNode user : users) {
      if (USERNAME.equals(user.path("username").asText())) {
        return requiredText(user, "id");
      }
    }
    throw new IllegalStateException(
        "Keycloak test user " + USERNAME + " was not found - realm import may have failed");
  }

  private void addOrganizationMember(String organizationId, String userId) {
    // Bare JSON string body, not a JSON object - confirmed live (any other shape returns HTTP
    // 415).
    send(
        "POST",
        adminBase().resolve("organizations/" + organizationId + "/members"),
        userId,
        201,
        204,
        409);
  }

  private void addOrganizationGroupMember(String organizationId, String groupId, String userId) {
    send(
        "PUT",
        adminBase()
            .resolve(
                "organizations/" + organizationId + "/groups/" + groupId + "/members/" + userId),
        null,
        204,
        409);
  }

  private String clientUuid() {
    String resolved = clientUuid;
    if (resolved != null) {
      return resolved;
    }
    String query = URLEncoder.encode(CLIENT_ID, StandardCharsets.UTF_8);
    JsonNode clients =
        send(
                "GET",
                URI.create(adminBase().resolve("clients").toString() + "?clientId=" + query),
                null,
                200)
            .body();
    for (JsonNode client : clients) {
      if (CLIENT_ID.equals(client.path("clientId").asText())) {
        resolved = requiredText(client, "id");
        clientUuid = resolved;
        return resolved;
      }
    }
    throw new IllegalStateException(
        "Keycloak client " + CLIENT_ID + " was not found - realm import may have failed");
  }

  private String authzenClientUuid() {
    String resolved = authzenClientUuid;
    if (resolved != null) {
      return resolved;
    }
    String query = URLEncoder.encode(AUTHZEN_CLIENT_ID, StandardCharsets.UTF_8);
    JsonNode clients =
        send(
                "GET",
                URI.create(adminBase().resolve("clients").toString() + "?clientId=" + query),
                null,
                200)
            .body();
    for (JsonNode client : clients) {
      if (AUTHZEN_CLIENT_ID.equals(client.path("clientId").asText())) {
        resolved = requiredText(client, "id");
        authzenClientUuid = resolved;
        return resolved;
      }
    }
    throw new IllegalStateException(
        "Keycloak client " + AUTHZEN_CLIENT_ID + " was not found - realm import may have failed");
  }

  private URI adminBase() {
    return URI.create(baseUrl() + "/admin/realms/" + REALM + "/");
  }

  private String baseUrl() {
    String issuer = issuer().toString();
    String suffix = "/realms/" + REALM;
    if (!issuer.endsWith(suffix)) {
      throw new IllegalStateException("Unexpected Keycloak issuer shape: " + issuer);
    }
    return issuer.substring(0, issuer.length() - suffix.length());
  }

  private String adminBearerToken() {
    String resolved = adminToken;
    if (resolved != null && System.nanoTime() < adminTokenExpiresAtNanos) {
      return resolved;
    }
    try {
      HttpRequest request =
          HttpRequest.newBuilder(
                  URI.create(baseUrl() + "/realms/master/protocol/openid-connect/token"))
              .header("Content-Type", "application/x-www-form-urlencoded")
              .POST(
                  HttpRequest.BodyPublishers.ofString(
                      "grant_type=password&client_id=admin-cli&username=admin&password=admin-integration-only"))
              .build();
      HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
      if (response.statusCode() != 200) {
        throw new IllegalStateException(
            "Keycloak admin token request returned HTTP "
                + response.statusCode()
                + ": "
                + response.body());
      }
      Matcher matcher = ACCESS_TOKEN.matcher(response.body());
      if (!matcher.find()) {
        throw new IllegalStateException("Keycloak admin token response has no access_token");
      }
      resolved = matcher.group(1);
      Matcher expiresMatcher = EXPIRES_IN.matcher(response.body());
      Duration ttl =
          expiresMatcher.find()
              ? Duration.ofSeconds(Long.parseLong(expiresMatcher.group(1)))
              : Duration.ofSeconds(60);
      Duration effectiveTtl =
          ttl.compareTo(TOKEN_REFRESH_SAFETY_MARGIN) > 0
              ? ttl.minus(TOKEN_REFRESH_SAFETY_MARGIN)
              : ttl;
      adminTokenExpiresAtNanos = System.nanoTime() + effectiveTtl.toNanos();
      adminToken = resolved;
      return resolved;
    } catch (InterruptedException interrupted) {
      Thread.currentThread().interrupt();
      throw new IllegalStateException(
          "Interrupted while obtaining a Keycloak admin token", interrupted);
    } catch (IOException failure) {
      throw new UncheckedIOException("Unable to obtain a Keycloak admin token", failure);
    }
  }

  private Response send(String method, URI uri, Object body, int... expectedStatuses) {
    try {
      HttpRequest.BodyPublisher publisher =
          body == null
              ? HttpRequest.BodyPublishers.noBody()
              : HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(body));
      HttpRequest request =
          HttpRequest.newBuilder(uri)
              .timeout(Duration.ofSeconds(30))
              .header("Authorization", "Bearer " + adminBearerToken())
              .header("Content-Type", "application/json")
              .method(method, publisher)
              .build();
      HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
      for (int expected : expectedStatuses) {
        if (response.statusCode() == expected) {
          JsonNode json =
              response.body().isBlank()
                  ? mapper.createObjectNode()
                  : mapper.readTree(response.body());
          return new Response(
              response.statusCode(), json, response.headers().firstValue("Location"));
        }
      }
      throw new IllegalStateException(
          "Keycloak Admin REST "
              + method
              + " "
              + uri
              + " returned HTTP "
              + response.statusCode()
              + ": "
              + response.body());
    } catch (InterruptedException interrupted) {
      Thread.currentThread().interrupt();
      throw new IllegalStateException("Interrupted during a Keycloak Admin REST call", interrupted);
    } catch (IOException failure) {
      throw new UncheckedIOException("Keycloak Admin REST is unavailable", failure);
    }
  }

  private static String requiredText(JsonNode node, String field) {
    String value = node.path(field).asText();
    if (value.isBlank()) {
      throw new IllegalStateException("Keycloak response is missing " + field);
    }
    return value;
  }

  private static String lastPathSegment(String uri) {
    return uri.substring(uri.lastIndexOf('/') + 1);
  }

  private static String realmJson() {
    try (InputStream stream = AuthzenKeycloakFixture.class.getResourceAsStream(REALM_RESOURCE)) {
      if (stream == null) {
        throw new IllegalStateException("Missing " + REALM_RESOURCE);
      }
      return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
    } catch (IOException failure) {
      throw new UncheckedIOException("Unable to load " + REALM_RESOURCE, failure);
    }
  }

  private record Response(int status, JsonNode body, Optional<String> location) {}
}
