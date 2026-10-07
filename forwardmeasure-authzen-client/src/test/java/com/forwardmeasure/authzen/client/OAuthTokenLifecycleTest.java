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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.forwardmeasure.authzen.AuthorizationUnavailableException;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * HTTP protocol and deterministic cache-boundary tests; real token issuance is covered separately.
 */
@Timeout(20)
class OAuthTokenLifecycleTest {
  private final AtomicInteger calls = new AtomicInteger();
  private final AtomicInteger status = new AtomicInteger(200);
  private final AtomicReference<String> response =
      new AtomicReference<>("{\"access_token\":\"first-fixture-token\",\"expires_in\":100}");
  private final AtomicReference<Map<String, String>> form = new AtomicReference<>();
  private final TestClock clock = new TestClock();
  private HttpServer server;
  private HttpClient http;
  private URI endpoint;

  @BeforeEach
  void start() throws Exception {
    http = HttpClient.newHttpClient();
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext(
        "/token",
        exchange -> {
          calls.incrementAndGet();
          String body =
              new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
          form.set(
              Arrays.stream(body.split("&"))
                  .map(part -> part.split("=", 2))
                  .collect(Collectors.toMap(part -> decode(part[0]), part -> decode(part[1]))));
          byte[] bytes = response.get().getBytes(StandardCharsets.UTF_8);
          exchange.sendResponseHeaders(status.get(), bytes.length == 0 ? -1 : bytes.length);
          if (bytes.length > 0) exchange.getResponseBody().write(bytes);
          exchange.close();
        });
    server.start();
    endpoint = URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/token");
  }

  @AfterEach
  void close() {
    server.stop(0);
    http.close();
  }

  @Test
  void cachedTokenRefreshesAtSafetyBoundaryAndOutageCannotReturnExpiredToken() {
    var supplier = supplier();
    assertEquals("first-fixture-token", supplier.bearerToken());
    clock.advance(Duration.ofSeconds(89));
    assertEquals("first-fixture-token", supplier.bearerToken());
    assertEquals(1, calls.get());
    clock.advance(Duration.ofSeconds(1));
    status.set(503);
    assertThrows(AuthorizationUnavailableException.class, supplier::bearerToken);
    assertEquals(2, calls.get());
    status.set(200);
    response.set("{\"access_token\":\"recovered-fixture-token\",\"expires_in\":1}");
    assertEquals("recovered-fixture-token", supplier.bearerToken());
    assertEquals(3, calls.get());
    clock.advance(Duration.ofSeconds(1));
    assertEquals("recovered-fixture-token", supplier.bearerToken());
    assertEquals(4, calls.get(), "One-second tokens must be refreshed at their expiry");
  }

  @Test
  void concurrentCallersShareOneTokenRequestAndOneRefresh() throws Exception {
    var supplier = supplier();
    try (var workers = Executors.newVirtualThreadPerTaskExecutor()) {
      for (int round = 0; round < 2; round++) {
        var ready = new CountDownLatch(12);
        var start = new CountDownLatch(1);
        List<Future<String>> futures = new ArrayList<>();
        for (int i = 0; i < 12; i++)
          futures.add(
              workers.submit(
                  () -> {
                    ready.countDown();
                    assertTrue(start.await(5, TimeUnit.SECONDS));
                    return supplier.bearerToken();
                  }));
        assertTrue(ready.await(5, TimeUnit.SECONDS));
        start.countDown();
        for (var future : futures)
          assertEquals("first-fixture-token", future.get(5, TimeUnit.SECONDS));
        assertEquals(round + 1, calls.get());
        clock.advance(Duration.ofSeconds(100));
      }
    }
  }

  @Test
  void reservedCharactersAndOrganizationScopeRemainDistinctFormValues() {
    var supplier =
        new OAuthClientCredentialsTokenSupplier(
            http,
            new ObjectMapper(),
            endpoint,
            "worker+east & west",
            "fixture=secret+&%",
            Duration.ofSeconds(2),
            "organization:tenant A+1");
    supplier.bearerToken();
    assertEquals(
        Map.of(
            "grant_type",
            "client_credentials",
            "client_id",
            "worker+east & west",
            "client_secret",
            "fixture=secret+&%",
            "scope",
            "organization:tenant A+1"),
        form.get());
    supplier().bearerToken();
    assertFalse(form.get().containsKey("scope"));
  }

  @Test
  void malformedAndIncompleteTokenResponsesAreNeverCached() {
    var supplier = supplier();
    for (String body :
        List.of(
            "{broken",
            "",
            "null",
            "[]",
            "{}",
            "{\"access_token\": \" \", \"expires_in\": 30}",
            "{\"access_token\":\"unusable\",\"expires_in\":0}",
            "{\"access_token\":\"unusable\",\"expires_in\":-10}")) {
      response.set(body);
      assertThrows(
          AuthorizationUnavailableException.class,
          supplier::bearerToken,
          "Invalid OAuth response must fail through the availability contract");
    }
    int rejected = calls.get();
    response.set("{\"access_token\":\"valid-fixture-token\",\"expires_in\":3600}");
    assertEquals("valid-fixture-token", supplier.bearerToken());
    assertEquals("valid-fixture-token", supplier.bearerToken());
    assertEquals(rejected + 1, calls.get());
  }

  @Test
  void cancelledRefreshPreservesInterruptionAndDoesNotPoisonNextAttempt() {
    var supplier = supplier();
    Thread.currentThread().interrupt();
    try {
      assertThrows(AuthorizationUnavailableException.class, supplier::bearerToken);
      assertTrue(Thread.currentThread().isInterrupted());
    } finally {
      Thread.interrupted();
    }
    assertEquals("first-fixture-token", supplier.bearerToken());
  }

  private OAuthClientCredentialsTokenSupplier supplier() {
    return new OAuthClientCredentialsTokenSupplier(
        http,
        new ObjectMapper(),
        endpoint,
        "fixture-client",
        "fixture-secret",
        Duration.ofSeconds(2),
        clock);
  }

  private static String decode(String value) {
    return URLDecoder.decode(value, StandardCharsets.UTF_8);
  }

  private static final class TestClock extends Clock {
    private Instant instant = Instant.parse("2026-10-07T00:00:00Z");

    void advance(Duration amount) {
      instant = instant.plus(amount);
    }

    @Override
    public ZoneId getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
      return Clock.fixed(instant, zone);
    }

    @Override
    public Instant instant() {
      return instant;
    }
  }
}
