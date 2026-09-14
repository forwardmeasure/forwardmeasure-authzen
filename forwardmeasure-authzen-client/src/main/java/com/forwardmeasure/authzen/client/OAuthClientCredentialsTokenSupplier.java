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
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

/**
 * Cached OAuth 2 client-credentials token source for authenticating AuthZEN PDP calls. Ported
 * verbatim from forwardmeasure-openworkflow's real {@code OAuthClientCredentialsTokenSupplier}.
 */
public final class OAuthClientCredentialsTokenSupplier implements BearerTokenSupplier {
  private final HttpClient client;
  private final ObjectMapper mapper;
  private final URI endpoint;
  private final String clientId;
  private final String clientSecret;
  private final Duration timeout;
  private final Clock clock;
  private volatile Token cached;

  public OAuthClientCredentialsTokenSupplier(
      HttpClient client,
      ObjectMapper mapper,
      URI endpoint,
      String clientId,
      String clientSecret,
      Duration timeout) {
    this(client, mapper, endpoint, clientId, clientSecret, timeout, Clock.systemUTC());
  }

  OAuthClientCredentialsTokenSupplier(
      HttpClient client,
      ObjectMapper mapper,
      URI endpoint,
      String clientId,
      String clientSecret,
      Duration timeout,
      Clock clock) {
    this.client = Objects.requireNonNull(client, "client");
    this.mapper = Objects.requireNonNull(mapper, "mapper");
    this.endpoint = Objects.requireNonNull(endpoint, "endpoint");
    this.clientId = requireText(clientId, "clientId");
    this.clientSecret = requireText(clientSecret, "clientSecret");
    this.timeout = Objects.requireNonNull(timeout, "timeout");
    this.clock = Objects.requireNonNull(clock, "clock");
  }

  @Override
  public String bearerToken() {
    Token available = cached;
    Instant now = clock.instant();
    if (available != null && available.refreshAfter().isAfter(now)) {
      return available.value();
    }
    synchronized (this) {
      available = cached;
      if (available == null || !available.refreshAfter().isAfter(now)) {
        cached = available = request(now);
      }
      return available.value();
    }
  }

  private Token request(Instant now) {
    String body =
        "grant_type=client_credentials&client_id="
            + encode(clientId)
            + "&client_secret="
            + encode(clientSecret);
    try {
      HttpResponse<String> response =
          client.send(
              HttpRequest.newBuilder(endpoint)
                  .timeout(timeout)
                  .header("Content-Type", "application/x-www-form-urlencoded")
                  .POST(HttpRequest.BodyPublishers.ofString(body))
                  .build(),
              HttpResponse.BodyHandlers.ofString());
      if (response.statusCode() != 200) {
        throw unavailable("OAuth token endpoint returned HTTP " + response.statusCode(), null);
      }
      JsonNode json = mapper.readTree(response.body());
      String token = json.path("access_token").asText();
      long expiresIn = json.path("expires_in").asLong();
      if (token.isBlank() || expiresIn < 1) {
        throw unavailable("OAuth token response is incomplete", null);
      }
      long refreshSeconds = Math.max(1, expiresIn - Math.min(30, expiresIn / 10));
      return new Token(token, now.plusSeconds(refreshSeconds));
    } catch (IOException failure) {
      throw unavailable("OAuth token endpoint is unavailable", failure);
    } catch (InterruptedException failure) {
      Thread.currentThread().interrupt();
      throw unavailable("OAuth token request was interrupted", failure);
    }
  }

  private static String encode(String value) {
    return URLEncoder.encode(value, StandardCharsets.UTF_8);
  }

  private static String requireText(String value, String name) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException(name + " must not be blank");
    }
    return value;
  }

  private static AuthorizationUnavailableException unavailable(String message, Throwable cause) {
    return new AuthorizationUnavailableException(message, cause);
  }

  private record Token(String value, Instant refreshAfter) {}
}
