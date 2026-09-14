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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.forwardmeasure.authzen.Action;
import com.forwardmeasure.authzen.ActiveOrganization;
import com.forwardmeasure.authzen.AuthorizationDecision;
import com.forwardmeasure.authzen.AuthorizationRequest;
import com.forwardmeasure.authzen.AuthorizationService;
import com.forwardmeasure.authzen.AuthorizationUnavailableException;
import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Fail-closed Keycloak 26.7 AuthZEN Evaluation/Evaluations adapter. Ported from
 * forwardmeasure-openworkflow's real {@code AuthzenAuthorizationService} - same wire shapes, same
 * caching, same tenant-mismatch guard, same fail-closed-on-anything-but-a-clean-200 behavior. One
 * necessary change: the origin calls {@code request.resolvedActionScope()} (an
 * openworkflow-specific method that suffixes a Human Task disposition code onto the action scope);
 * the shared {@link AuthorizationRequest} here has no such method - {@code action} is a real, typed
 * {@link Action}, per that type's own javadoc - so this class calls {@code
 * request.action().scope()} to get the real wire string. Any product needing scope-resolution logic
 * beyond a plain enum constant (fowf's own Human Task case included) supplies its own small {@code
 * Action} implementation for that one case before constructing the request, not a raw string this
 * shared client would have no way to validate.
 */
public final class AuthzenAuthorizationService implements AuthorizationService {
  private final HttpClient client;
  private final ObjectMapper mapper;
  private final BearerTokenSupplier tokenSupplier;
  private final AuthzenConfiguration configuration;
  private final Clock clock;
  private final ConcurrentHashMap<CacheKey, CachedDecision> cache = new ConcurrentHashMap<>();

  public AuthzenAuthorizationService(
      HttpClient client,
      ObjectMapper mapper,
      BearerTokenSupplier tokenSupplier,
      AuthzenConfiguration configuration) {
    this(client, mapper, tokenSupplier, configuration, Clock.systemUTC());
  }

  AuthzenAuthorizationService(
      HttpClient client,
      ObjectMapper mapper,
      BearerTokenSupplier tokenSupplier,
      AuthzenConfiguration configuration,
      Clock clock) {
    this.client = Objects.requireNonNull(client, "client");
    this.mapper = Objects.requireNonNull(mapper, "mapper");
    this.tokenSupplier = Objects.requireNonNull(tokenSupplier, "tokenSupplier");
    this.configuration = Objects.requireNonNull(configuration, "configuration");
    this.clock = Objects.requireNonNull(clock, "clock");
  }

  @Override
  public AuthorizationDecision evaluate(AuthorizationRequest request) {
    Objects.requireNonNull(request, "request");
    CacheKey key = CacheKey.from(request, configuration.policyVersion());
    CachedDecision cached = cache.get(key);
    Instant now = clock.instant();
    if (cached != null && cached.expiresAt().isAfter(now)) {
      return new AuthorizationDecision(
          cached.permitted(), request.correlationId(), Map.of("cache", true));
    }
    JsonNode response =
        post(configuration.evaluationEndpoint(), request.correlationId(), body(request));
    boolean decision = requiredDecision(response);
    cache(key, decision, now);
    return new AuthorizationDecision(decision, request.correlationId(), responseContext(response));
  }

  @Override
  public List<AuthorizationDecision> evaluateBatch(List<AuthorizationRequest> requests) {
    List<AuthorizationRequest> immutable = List.copyOf(requests);
    if (immutable.isEmpty()) {
      return List.of();
    }
    AuthorizationRequest first = immutable.getFirst();
    for (AuthorizationRequest request : immutable) {
      if (!request.organization().equals(first.organization())
          || !request.correlationId().equals(first.correlationId())) {
        throw new IllegalArgumentException(
            "A batch must use one active Organization and one audit correlation ID");
      }
    }
    Map<String, Object> payload = new LinkedHashMap<>();
    payload.put("subject", subject(first.organization()));
    payload.put("options", Map.of("evaluations_semantic", "execute_all"));
    payload.put("evaluations", immutable.stream().map(this::evaluationItem).toList());
    JsonNode response =
        post(configuration.evaluationsEndpoint(), first.correlationId(), payload)
            .get("evaluations");
    if (response == null || !response.isArray() || response.size() != immutable.size()) {
      throw unavailable("AuthZEN batch response did not contain one decision per request", null);
    }
    List<AuthorizationDecision> decisions = new ArrayList<>(immutable.size());
    for (int index = 0; index < immutable.size(); index++) {
      JsonNode item = response.get(index);
      decisions.add(
          new AuthorizationDecision(
              requiredDecision(item), immutable.get(index).correlationId(), responseContext(item)));
    }
    return List.copyOf(decisions);
  }

  private JsonNode post(java.net.URI endpoint, String correlationId, Object payload) {
    String token = tokenSupplier.bearerToken();
    if (token == null || token.isBlank()) {
      throw unavailable("AuthZEN bearer token is missing", null);
    }
    try {
      String requestBody = mapper.writeValueAsString(payload);
      HttpRequest request =
          HttpRequest.newBuilder(endpoint)
              .timeout(configuration.requestTimeout())
              .header("Authorization", "Bearer " + token)
              .header("Content-Type", "application/json")
              .header("X-Request-ID", correlationId)
              .POST(HttpRequest.BodyPublishers.ofString(requestBody))
              .build();
      HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
      if (response.statusCode() != 200) {
        throw unavailable("AuthZEN rejected evaluation with HTTP " + response.statusCode(), null);
      }
      String echoed = response.headers().firstValue("X-Request-ID").orElse("");
      if (!correlationId.equals(echoed)) {
        throw unavailable("AuthZEN did not preserve audit correlation", null);
      }
      return mapper.readTree(response.body());
    } catch (JsonProcessingException exception) {
      throw unavailable("AuthZEN returned unusable JSON", exception);
    } catch (IOException exception) {
      throw unavailable("AuthZEN is unavailable", exception);
    } catch (InterruptedException exception) {
      Thread.currentThread().interrupt();
      throw unavailable("AuthZEN evaluation was interrupted", exception);
    }
  }

  private Map<String, Object> body(AuthorizationRequest request) {
    Map<String, Object> payload = new LinkedHashMap<>(evaluationItem(request));
    payload.put("subject", subject(request.organization()));
    return payload;
  }

  private Map<String, Object> evaluationItem(AuthorizationRequest request) {
    Map<String, Object> context = new LinkedHashMap<>(request.context());
    context.put("active_organization_id", request.organization().organizationId());
    context.put("tenant_id", request.organization().tenantId().toString());
    context.put("policy_version", configuration.policyVersion());
    Map<String, Object> resourceProperties = new LinkedHashMap<>(request.resource().properties());
    Object requestedTenant =
        resourceProperties.putIfAbsent("tenant_id", request.organization().tenantId().toString());
    if (requestedTenant != null
        && !request.organization().tenantId().toString().equals(requestedTenant.toString())) {
      return Map.of(
          "resource", Map.of("type", request.resource().type(), "id", "tenant-mismatch"),
          "action", Map.of("name", "tenant:mismatch"),
          "context", Map.copyOf(context));
    }
    return Map.of(
        "resource",
        Map.of(
            "type", request.resource().type(),
            "id", request.resource().id(),
            "properties", Map.copyOf(resourceProperties)),
        "action",
        Map.of("name", request.action().scope()),
        "context",
        Map.copyOf(context));
  }

  private static Map<String, Object> subject(ActiveOrganization organization) {
    List<String> roles = organization.organizationRoles().stream().sorted().toList();
    return Map.of(
        "type",
        "user",
        "id",
        organization.actorId(),
        "properties",
        Map.of(
            "organization_id",
            organization.organizationId(),
            "active_organization_id",
            organization.organizationId(),
            "tenant_id",
            organization.tenantId().toString(),
            "organization_roles",
            roles,
            "roles",
            roles));
  }

  private boolean requiredDecision(JsonNode node) {
    JsonNode decision = node == null ? null : node.get("decision");
    if (decision == null || !decision.isBoolean()) {
      throw unavailable("AuthZEN response has no boolean decision", null);
    }
    return decision.booleanValue();
  }

  @SuppressWarnings("unchecked")
  private Map<String, Object> responseContext(JsonNode node) {
    JsonNode context = node == null ? null : node.get("context");
    return context == null || !context.isObject()
        ? Map.of()
        : mapper.convertValue(context, Map.class);
  }

  private void cache(CacheKey key, boolean permitted, Instant now) {
    if (cache.size() >= configuration.maximumCacheEntries()) {
      cache.entrySet().removeIf(entry -> !entry.getValue().expiresAt().isAfter(now));
      if (cache.size() >= configuration.maximumCacheEntries()) {
        cache.clear();
      }
    }
    cache.put(key, new CachedDecision(permitted, now.plus(configuration.decisionTtl())));
  }

  private static AuthorizationUnavailableException unavailable(String message, Throwable cause) {
    return cause == null
        ? new AuthorizationUnavailableException(message)
        : new AuthorizationUnavailableException(message, cause);
  }

  private record CachedDecision(boolean permitted, Instant expiresAt) {}

  private record CacheKey(
      ActiveOrganization organization,
      Object resource,
      Object action,
      Object context,
      String policyVersion) {
    static CacheKey from(AuthorizationRequest request, String policyVersion) {
      return new CacheKey(
          request.organization(),
          request.resource(),
          request.action(),
          request.context(),
          policyVersion);
    }
  }
}
