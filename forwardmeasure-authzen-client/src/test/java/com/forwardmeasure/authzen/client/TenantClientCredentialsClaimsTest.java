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

import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.forwardmeasure.authzen.AuthorizationUnavailableException;
import com.forwardmeasure.jpa.tenancy.Did;
import com.forwardmeasure.jpa.tenancy.TenantId;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class TenantClientCredentialsClaimsTest {
  @Test
  void rejectsMalformedMultiTenantAndWrongTenantScopedResponses() throws Exception {
    ObjectMapper json = new ObjectMapper();
    var requested = Map.of("forwardmeasure.tenant-did", List.of("did:web:a.example.test"));
    var other = Map.of("forwardmeasure.tenant-did", List.of("did:web:b.example.test"));
    String discovery = jwt(json, Map.of("organization", Map.of("a", requested)));
    for (String scoped :
        List.of(
            "not-a-jwt",
            jwt(json, Map.of("organization", Map.of("b", other))),
            jwt(json, Map.of("organization", Map.of("a", requested, "b", other))),
            jwt(json, Map.of("organization", Map.of())))) {
      HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
      server.createContext(
          "/token",
          exchange -> {
            String form =
                new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            String token = form.contains("organization%3A*") ? discovery : scoped;
            byte[] body = json.writeValueAsBytes(Map.of("access_token", token, "expires_in", 60));
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
          });
      server.start();
      try {
        var credentials =
            new TenantClientCredentials(
                URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/token"),
                "fixture",
                "fixture-only");
        assertThrows(
            AuthorizationUnavailableException.class,
            () -> credentials.bearerToken(TenantId.forDid(Did.parse("did:web:a.example.test"))));
      } finally {
        server.stop(0);
      }
    }
  }

  private static String jwt(ObjectMapper json, Map<String, ?> claims) throws Exception {
    // This transport fixture deliberately returns malformed/untrusted JWT bodies. Real issuance is
    // independently exercised by TenantClientCredentialsKeycloakIntegrationTest.
    return "e30."
        + Base64.getUrlEncoder().withoutPadding().encodeToString(json.writeValueAsBytes(claims))
        + ".fixture";
  }
}
