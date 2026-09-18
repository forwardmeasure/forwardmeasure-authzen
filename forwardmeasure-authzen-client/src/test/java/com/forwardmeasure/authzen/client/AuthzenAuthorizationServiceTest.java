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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.forwardmeasure.authzen.Action;
import com.forwardmeasure.authzen.ActiveOrganization;
import com.forwardmeasure.authzen.AuthorizationRequest;
import com.forwardmeasure.authzen.AuthorizationResource;
import com.forwardmeasure.authzen.AuthorizationUnavailableException;
import com.forwardmeasure.jpa.tenancy.TenantDatabase;
import com.forwardmeasure.jpa.tenancy.TenantId;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Ported from forwardmeasure-openworkflow's real {@code AuthzenAuthorizationServiceTest} - same
 * real in-process HTTP server, same wire-shape assertions - adapted for the shared library's own
 * generic {@link AuthorizationResource} (no product-specific static factories here) and plain
 * {@code String} action (no {@code AuthorizationAction} enum here).
 */
class AuthzenAuthorizationServiceTest {
  private final ObjectMapper mapper = new ObjectMapper();
  private final AtomicInteger calls = new AtomicInteger();
  private final AtomicReference<String> response = new AtomicReference<>("{\"decision\":true}");
  private final AtomicReference<Integer> status = new AtomicReference<>(200);
  private final AtomicReference<JsonNode> requestBody = new AtomicReference<>();
  private HttpServer server;
  private URI baseUri;

  @BeforeEach
  void startServer() throws IOException {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/evaluation", this::handle);
    server.createContext("/evaluations", this::handle);
    server.start();
    baseUri = URI.create("http://127.0.0.1:" + server.getAddress().getPort());
  }

  @AfterEach
  void stopServer() {
    server.stop(0);
  }

  @Test
  void sendsOnlyActiveOrganizationRolesAndPreservesAuditCorrelation() {
    AuthorizationRequest request =
        request("org-active", Set.of("workflow-author"), "correlation-1");
    assertTrue(service(() -> "token").evaluate(request).permitted());
    JsonNode sent = requestBody.get();
    assertEquals("11111111-1111-1111-1111-111111111111", sent.at("/subject/id").textValue());
    assertEquals("org-active", sent.at("/subject/properties/active_organization_id").textValue());
    assertEquals("org-active", sent.at("/subject/properties/organization_id").textValue());
    assertEquals(
        "workflow-author", sent.at("/subject/properties/organization_roles/0").textValue());
    assertEquals("workflow-author", sent.at("/subject/properties/roles/0").textValue());
    assertEquals("widget:read", sent.at("/action/name").textValue());
    assertFalse(sent.toString().contains("realm_access"));
    assertFalse(sent.toString().contains("resource_access"));
  }

  @Test
  void failuresMissingTokenAndUnusableResponsesFailClosed() {
    assertThrows(
        AuthorizationUnavailableException.class,
        () -> service(() -> "").evaluate(request("org", Set.of(), "missing-token")));
    status.set(503);
    assertThrows(
        AuthorizationUnavailableException.class,
        () -> service(() -> "token").evaluate(request("org", Set.of(), "failed")));
    status.set(200);
    response.set("{}");
    assertThrows(
        AuthorizationUnavailableException.class,
        () -> service(() -> "token").evaluate(request("org", Set.of(), "unusable")));
  }

  @Test
  void cachesOnlyUsableDecisionsWithinTheFullOrganizationContext() {
    AuthzenAuthorizationService service = service(() -> "token");
    AuthorizationRequest first = request("org-a", Set.of("workflow-author"), "cache-1");
    service.evaluate(first);
    service.evaluate(first);
    service.evaluate(request("org-b", Set.of("workflow-author"), "cache-2"));
    assertEquals(2, calls.get());
  }

  @Test
  void batchUsesExecuteAllAndReturnsEveryDecision() {
    response.set("{\"evaluations\":[{\"decision\":true},{\"decision\":false}]}");
    AuthorizationRequest first = request("org", Set.of("workflow-author"), "batch");
    AuthorizationRequest second =
        new AuthorizationRequest(
            first.organization(),
            new AuthorizationResource("widget", "widgets", Map.of()),
            TestAction.DELETE,
            "batch",
            Map.of());
    var decisions = service(() -> "token").evaluateBatch(List.of(first, second));
    assertTrue(decisions.get(0).permitted());
    assertFalse(decisions.get(1).permitted());
    assertEquals("execute_all", requestBody.get().at("/options/evaluations_semantic").textValue());
  }

  private AuthzenAuthorizationService service(BearerTokenSupplier tokens) {
    return new AuthzenAuthorizationService(
        HttpClient.newHttpClient(),
        mapper,
        tokens,
        new AuthzenConfiguration(
            baseUri.resolve("/evaluation"),
            baseUri.resolve("/evaluations"),
            Duration.ofSeconds(2),
            Duration.ofSeconds(30),
            100,
            "test-v1"));
  }

  private AuthorizationRequest request(
      String organizationId, Set<String> roles, String correlation) {
    return new AuthorizationRequest(
        new ActiveOrganization(
            new TenantId(UUID.fromString("01234567-89ab-cdef-0123-456789abcdef")),
            TenantDatabase.forAlias("authzenauthorizationservicetest"),
            organizationId,
            "11111111-1111-1111-1111-111111111111",
            roles),
        new AuthorizationResource("widget", "widgets", Map.of()),
        TestAction.READ,
        correlation,
        Map.of());
  }

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

  private void handle(HttpExchange exchange) throws IOException {
    calls.incrementAndGet();
    requestBody.set(mapper.readTree(exchange.getRequestBody()));
    String correlation = exchange.getRequestHeaders().getFirst("X-Request-ID");
    exchange.getResponseHeaders().add("Content-Type", "application/json");
    exchange.getResponseHeaders().add("X-Request-ID", correlation);
    byte[] bytes = response.get().getBytes(StandardCharsets.UTF_8);
    exchange.sendResponseHeaders(status.get(), bytes.length);
    exchange.getResponseBody().write(bytes);
    exchange.close();
  }
}
