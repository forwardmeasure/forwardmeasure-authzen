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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.forwardmeasure.authzen.AuthorizationUnavailableException;
import com.forwardmeasure.authzen.testkit.AuthzenKeycloakFixture;
import com.forwardmeasure.jpa.tenancy.Did;
import com.forwardmeasure.jpa.tenancy.TenantId;
import java.net.URI;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import org.junit.jupiter.api.Test;

class TenantClientCredentialsKeycloakIntegrationTest {
  private static final ObjectMapper JSON = new ObjectMapper();

  @Test
  void concurrentCallsSelectExactlyTheirTenantAndNeverFallBackForANonMember() throws Exception {
    try (AuthzenKeycloakFixture keycloak = AuthzenKeycloakFixture.start()) {
      String clientId = "tenant-caller";
      String secret = "tenant-caller-integration-only";
      keycloak.createServiceAccountClient(clientId, secret);
      Did a = Did.parse("did:web:tenant-a.example.test");
      Did b = Did.parse("did:web:tenant-b.example.test");
      Did denied = Did.parse("did:web:tenant-denied.example.test");
      String aOrg = keycloak.provisionTenant("tenant-a", a, "worker");
      String bOrg = keycloak.provisionTenant("tenant-b", b, "worker");
      String deniedOrg = keycloak.provisionTenant("tenant-denied", denied, "worker");
      keycloak.addServiceAccountToOrganization(aOrg, clientId, "worker");
      keycloak.addServiceAccountToOrganization(bOrg, clientId, "worker");
      TenantClientCredentials tokens =
          new TenantClientCredentials(
              URI.create(keycloak.issuer() + "/protocol/openid-connect/token"), clientId, secret);
      List<Callable<Void>> calls = new ArrayList<>();
      for (int i = 0; i < 40; i++) {
        boolean first = i % 2 == 0;
        calls.add(
            () -> {
              Did did = first ? a : b;
              String alias = first ? "tenant-a" : "tenant-b";
              String token = tokens.bearerToken(TenantId.forDid(did));
              JsonNode claim =
                  JSON.readTree(Base64.getUrlDecoder().decode(token.split("\\.")[1]))
                      .required("organization");
              assertEquals(1, claim.size());
              assertEquals(
                  did.value(),
                  claim.required(alias).required("forwardmeasure.tenant-did").get(0).asText());
              return null;
            });
      }
      try (var executor = Executors.newFixedThreadPool(4)) {
        for (var result : executor.invokeAll(calls)) {
          result.get();
        }
      }
      assertThrows(
          AuthorizationUnavailableException.class,
          () -> tokens.bearerToken(TenantId.forDid(denied)));
      // A tenant provisioned at runtime must become usable immediately, without discovery TTL lag.
      keycloak.addServiceAccountToOrganization(deniedOrg, clientId, "worker");
      assertEquals(
          1,
          JSON.readTree(
                  Base64.getUrlDecoder()
                      .decode(tokens.bearerToken(TenantId.forDid(denied)).split("\\.")[1]))
              .required("organization")
              .size());
      // A denial must not replace either tenant's token with a global/fallback token.
      assertEquals(
          1,
          JSON.readTree(
                  Base64.getUrlDecoder()
                      .decode(tokens.bearerToken(TenantId.forDid(a)).split("\\.")[1]))
              .required("organization")
              .size());
    }
  }
}
