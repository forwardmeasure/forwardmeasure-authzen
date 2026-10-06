/*
 * Licensed to the Apache Software Foundation (ASF) under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with the License. You may obtain a
 * copy of the License at https://www.apache.org/licenses/LICENSE-2.0 Unless required by applicable
 * law or agreed to in writing, software distributed under the License is distributed on an "AS IS"
 * BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License
 * for the specific language governing permissions and limitations under the License.
 */
package com.forwardmeasure.authzen.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.forwardmeasure.authzen.AuthorizationUnavailableException;
import com.forwardmeasure.jpa.tenancy.Did;
import com.forwardmeasure.jpa.tenancy.TenantId;
import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Tenant-specific Keycloak tokens, with a bounded cache. Membership discovery is obtained directly
 * from the configured OAuth token endpoint, never from an incoming unverified JWT. A discovery
 * token is never returned to an API caller: every returned token names exactly the requested
 * tenant.
 */
public final class TenantClientCredentials {
  private static final int MAXIMUM_CACHED_TENANTS = 256;
  private final HttpClient http;
  private final ObjectMapper mapper;
  private final URI endpoint;
  private final String clientId;
  private final String secret;
  private final Duration timeout;
  private final Map<TenantId, OAuthClientCredentialsTokenSupplier> scoped =
      new LinkedHashMap<>(16, 0.75f, true);

  public TenantClientCredentials(URI endpoint, String clientId, String secret) {
    this(
        HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build(),
        new ObjectMapper(),
        endpoint,
        clientId,
        secret,
        Duration.ofSeconds(30));
  }

  public TenantClientCredentials(
      HttpClient http,
      ObjectMapper mapper,
      URI endpoint,
      String clientId,
      String secret,
      Duration timeout) {
    this.http = Objects.requireNonNull(http, "http");
    this.mapper = Objects.requireNonNull(mapper, "mapper");
    this.endpoint = Objects.requireNonNull(endpoint, "endpoint");
    this.clientId = Objects.requireNonNull(clientId, "clientId");
    this.secret = Objects.requireNonNull(secret, "secret");
    this.timeout = Objects.requireNonNull(timeout, "timeout");
  }

  public String bearerToken(TenantId tenant) {
    Objects.requireNonNull(tenant, "tenant");
    OAuthClientCredentialsTokenSupplier tokens;
    synchronized (scoped) {
      tokens = scoped.get(tenant);
    }
    if (tokens == null) {
      // Refresh discovery on each new tenant: membership may have been granted after a prior call.
      String alias = selectAlias(organizations(supplier("organization:*").bearerToken()), tenant);
      OAuthClientCredentialsTokenSupplier candidate = supplier("organization:" + alias);
      synchronized (scoped) {
        tokens = scoped.get(tenant);
        if (tokens == null) {
          if (scoped.size() >= MAXIMUM_CACHED_TENANTS) {
            scoped.remove(scoped.keySet().iterator().next());
          }
          scoped.put(tenant, candidate);
          tokens = candidate;
        }
      }
    }
    String token = tokens.bearerToken();
    JsonNode organizations = organizations(token);
    if (organizations.size() != 1) {
      throw unavailable("OAuth token must select exactly one Organization");
    }
    selectAlias(organizations, tenant);
    return token;
  }

  private OAuthClientCredentialsTokenSupplier supplier(String scope) {
    return new OAuthClientCredentialsTokenSupplier(
        http, mapper, endpoint, clientId, secret, timeout, scope);
  }

  private JsonNode organizations(String token) {
    try {
      String[] parts = token.split("\\.", -1);
      if (parts.length != 3) {
        throw unavailable("OAuth token endpoint did not return a JWT");
      }
      JsonNode organizations =
          mapper.readTree(Base64.getUrlDecoder().decode(parts[1])).path("organization");
      if (!organizations.isObject()) {
        throw unavailable("OAuth token has no Organization memberships");
      }
      return organizations;
    } catch (java.io.IOException | IllegalArgumentException failure) {
      throw new AuthorizationUnavailableException(
          "OAuth Organization claims are malformed", failure);
    }
  }

  private static String selectAlias(JsonNode organizations, TenantId expected) {
    String selected = null;
    var entries = organizations.fields();
    while (entries.hasNext()) {
      var entry = entries.next();
      JsonNode did = entry.getValue().get("forwardmeasure.tenant-did");
      if (did != null && did.isArray() && did.size() == 1) {
        did = did.get(0);
      }
      if (did == null || !did.isTextual()) {
        continue;
      }
      TenantId candidate;
      try {
        candidate = TenantId.forDid(Did.parse(did.textValue()));
      } catch (IllegalArgumentException malformed) {
        throw unavailable("OAuth Organization contains an invalid tenant DID");
      }
      if (expected.equals(candidate)) {
        if (selected != null || !entry.getKey().matches("[A-Za-z0-9._-]+")) {
          throw unavailable("OAuth Organization selection is ambiguous or malformed");
        }
        selected = entry.getKey();
      }
    }
    if (selected == null) {
      throw unavailable("Service account is not a member of the requested tenant");
    }
    return selected;
  }

  private static AuthorizationUnavailableException unavailable(String message) {
    return new AuthorizationUnavailableException(message, null);
  }
}
