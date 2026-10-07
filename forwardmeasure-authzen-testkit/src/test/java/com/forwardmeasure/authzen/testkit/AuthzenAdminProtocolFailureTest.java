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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.forwardmeasure.jpa.tenancy.Did;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.UnaryOperator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.parallel.ResourceLock;

/** Real Keycloak provisioning with explicitly corrupted Admin REST responses, never a fake PDP. */
@ResourceLock("java.net.ProxySelector.default")
class AuthzenAdminProtocolFailureTest {
  private static final ObjectMapper JSON = new ObjectMapper();

  @Test
  @Timeout(120)
  void incompleteAdminResponsesCannotSilentlyGrantAccessAndCanBeRetried() throws Exception {
    try (var proxy = new AdminResponseFaultProxy();
        var fixture = AuthzenKeycloakFixture.start()) {
      var did = Did.parse("did:fwmtest:tenant:protocol-faults");
      proxy.corrupt(
          "/realms/master/protocol/openid-connect/token",
          node -> {
            ((ObjectNode) node).remove("access_token");
            return node;
          });
      rejected(proxy, "no access_token", () -> fixture.provisionTenant("protocol", did, "reader"));
      // Some compatible token endpoints omit expires_in. Keep a real signed token and verify
      // the documented fallback can actually provision the organization.
      proxy.corrupt(
          "/realms/master/protocol/openid-connect/token",
          node -> {
            ((ObjectNode) node).remove("expires_in");
            return node;
          });
      String org = fixture.provisionTenant("protocol", did, "reader");
      proxy.assertConsumed();
      proxy.corrupt("/groups", ignored -> JSON.createArrayNode());
      rejected(
          proxy,
          "did not return the created Organization Group",
          () -> fixture.grantOrganizationClientRole(org, "worker"));
      fixture.grantOrganizationClientRole(org, "worker");

      // A successful POST alone is insufficient: each returned identifier must be established
      // before a permission can be installed. Dropped discovery responses fail explicitly.
      for (String kind : List.of("resource", "policy", "scope")) {
        proxy.corrupt("/authz/resource-server/" + kind, ignored -> JSON.createArrayNode());
        rejected(
            proxy,
            "did not return the created",
            () ->
                fixture.grantResourceAuthorization(
                    org,
                    "fixture-resource",
                    "population/one",
                    "protocol-read",
                    "reader",
                    Set.of("fixture:read")));
      }
      fixture.grantResourceAuthorization(
          org,
          "fixture-resource",
          "population/one",
          "protocol-read",
          "reader",
          Set.of("fixture:read"));
      try (var http = HttpClient.newHttpClient()) {
        assertTrue(
            AuthzenFixtureIntegrationTest.decision(
                fixture,
                http,
                AuthzenFixtureIntegrationTest.actor(fixture.mintUserToken()),
                "fixture:read"));
        assertFalse(
            AuthzenFixtureIntegrationTest.decision(
                fixture,
                http,
                AuthzenFixtureIntegrationTest.actor(fixture.mintUserToken()),
                "fixture:delete"));
      }
    }
  }

  private static void rejected(
      AdminResponseFaultProxy proxy,
      String expected,
      org.junit.jupiter.api.function.Executable operation) {
    var failure = assertThrows(IllegalStateException.class, operation);
    assertTrue(failure.getMessage().contains(expected), failure.getMessage());
    proxy.assertConsumed();
  }

  private record Fault(String suffix, UnaryOperator<JsonNode> corrupt) {}

  /**
   * Routes only local fixture Admin REST through a one-shot response fault; all other traffic
   * retains the original selector. The transport still talks to the real server on every call.
   */
  private static final class AdminResponseFaultProxy implements AutoCloseable {
    private final ProxySelector original = ProxySelector.getDefault();
    private final HttpClient upstream;
    private final HttpServer server;
    private final AtomicReference<Fault> fault = new AtomicReference<>();

    AdminResponseFaultProxy() throws IOException {
      upstream =
          HttpClient.newBuilder()
              .proxy(
                  new ProxySelector() {
                    public List<Proxy> select(URI uri) {
                      return List.of(Proxy.NO_PROXY);
                    }

                    public void connectFailed(
                        URI uri, SocketAddress address, IOException failure) {}
                  })
              .build();
      server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
      server.createContext(
          "/",
          exchange -> {
            try {
              URI uri = exchange.getRequestURI();
              byte[] requestBody = exchange.getRequestBody().readAllBytes();
              var builder =
                  HttpRequest.newBuilder(uri)
                      .method(
                          exchange.getRequestMethod(),
                          HttpRequest.BodyPublishers.ofByteArray(requestBody));
              for (String header : List.of("Authorization", "Content-Type")) {
                String value = exchange.getRequestHeaders().getFirst(header);
                if (value != null) builder.header(header, value);
              }
              var response =
                  upstream.send(builder.build(), HttpResponse.BodyHandlers.ofByteArray());
              byte[] bytes = response.body();
              Fault pending = fault.get();
              boolean token = uri.getPath().endsWith("/protocol/openid-connect/token");
              if (pending != null
                  && uri.getPath().endsWith(pending.suffix())
                  && (token || exchange.getRequestMethod().equals("GET"))
                  && fault.compareAndSet(pending, null)) {
                if (response.statusCode() != 200)
                  throw new IOException("Fault target did not succeed");
                bytes = JSON.writeValueAsBytes(pending.corrupt().apply(JSON.readTree(bytes)));
              }
              for (String header : List.of("Content-Type", "Location")) {
                response
                    .headers()
                    .firstValue(header)
                    .ifPresent(value -> exchange.getResponseHeaders().set(header, value));
              }
              exchange.sendResponseHeaders(
                  response.statusCode(), bytes.length == 0 ? -1 : bytes.length);
              if (bytes.length != 0) exchange.getResponseBody().write(bytes);
            } catch (InterruptedException interrupted) {
              Thread.currentThread().interrupt();
              throw new IOException(interrupted);
            } finally {
              exchange.close();
            }
          });
      server.start();
      Proxy route = new Proxy(Proxy.Type.HTTP, server.getAddress());
      ProxySelector.setDefault(
          new ProxySelector() {
            public List<Proxy> select(URI uri) {
              boolean local = Set.of("localhost", "127.0.0.1").contains(uri.getHost());
              if (local
                  && (uri.getPath().startsWith("/admin/")
                      || uri.getPath().equals("/realms/master/protocol/openid-connect/token"))) {
                return List.of(route);
              }
              return original == null ? List.of(Proxy.NO_PROXY) : original.select(uri);
            }

            public void connectFailed(URI uri, SocketAddress address, IOException failure) {
              if (original != null) original.connectFailed(uri, address, failure);
            }
          });
    }

    void corrupt(String suffix, UnaryOperator<JsonNode> corrupt) {
      assertNull(fault.getAndSet(new Fault(suffix, corrupt)), "Unconsumed previous fault");
    }

    void assertConsumed() {
      assertNull(fault.get(), "The real request did not encounter its fault");
    }

    @Override
    public void close() {
      ProxySelector.setDefault(original);
      server.stop(0);
      upstream.close();
    }
  }
}
