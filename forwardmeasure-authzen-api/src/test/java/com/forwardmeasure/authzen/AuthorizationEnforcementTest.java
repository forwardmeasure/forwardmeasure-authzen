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
package com.forwardmeasure.authzen;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.forwardmeasure.jpa.tenancy.TenantId;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import org.junit.jupiter.api.Test;

class AuthorizationEnforcementTest {
  private enum TestAction implements Action {
    READ,
    WRITE;

    public String scope() {
      return "population:" + name().toLowerCase(java.util.Locale.ROOT);
    }
  }

  @Test
  void actionsDoNotImplyUnrelatedPermissionsByDefault() {
    assertTrue(TestAction.READ.implies(TestAction.READ));
    assertFalse(TestAction.READ.implies(TestAction.WRITE));
    assertFalse(TestAction.READ.implies(null));
  }

  private final AuthorizationRequest request =
      new AuthorizationRequest(
          new ActiveOrganization(new TenantId(UUID.randomUUID()), "org", "actor", Set.of()),
          new AuthorizationResource("population", "population-1", Map.of()),
          TestAction.READ,
          "request-correlation",
          Map.of());

  @Test
  void explicitPermitAllowsOperationAndExplicitDenialRetainsRequestCorrelation() {
    assertDoesNotThrow(
        () ->
            service(r -> new AuthorizationDecision(true, r.correlationId(), Map.of()))
                .requireAuthorized(request));
    var denied =
        assertThrows(
            AuthorizationDeniedException.class,
            () ->
                service(r -> new AuthorizationDecision(false, r.correlationId(), Map.of()))
                    .requireAuthorized(request));
    assertTrue(denied.getMessage().contains(request.correlationId()));
  }

  @Test
  void unavailablePolicyDecisionNeverBecomesPermissionOrAnOrdinaryDenial() {
    var cause = new IOException("PDP connection failed");
    var unavailable = new AuthorizationUnavailableException("PDP unavailable", cause);
    assertSame(
        unavailable,
        assertThrows(
            AuthorizationUnavailableException.class,
            () ->
                service(
                        r -> {
                          throw unavailable;
                        })
                    .requireAuthorized(request)));
    assertSame(cause, unavailable.getCause());
    var invalid = new AuthorizationUnavailableException("Invalid PDP response");
    assertSame(
        invalid,
        assertThrows(
            AuthorizationUnavailableException.class,
            () ->
                service(
                        r -> {
                          throw invalid;
                        })
                    .requireAuthorized(request)));
  }

  @Test
  void decisionContextIsAnImmutableSnapshotAndRequiresCorrelation() {
    var context = new HashMap<String, Object>();
    context.put("policy", "version-1");
    var decision = new AuthorizationDecision(false, "decision-1", context);
    context.put("policy", "version-2");
    assertFalse(decision.permitted());
    assertEquals("version-1", decision.context().get("policy"));
    assertThrows(UnsupportedOperationException.class, () -> decision.context().put("permit", true));
    for (String correlation : new String[] {null, " ", ""}) {
      assertThrows(
          IllegalArgumentException.class,
          () -> new AuthorizationDecision(true, correlation, Map.of()));
      assertThrows(
          IllegalArgumentException.class,
          () ->
              new AuthorizationRequest(
                  request.organization(),
                  request.resource(),
                  request.action(),
                  correlation,
                  Map.of()));
    }
    assertThrows(NullPointerException.class, () -> new AuthorizationDecision(true, "id", null));
  }

  private static AuthorizationService service(
      Function<AuthorizationRequest, AuthorizationDecision> evaluator) {
    return new AuthorizationService() {
      public AuthorizationDecision evaluate(AuthorizationRequest request) {
        return evaluator.apply(request);
      }

      public List<AuthorizationDecision> evaluateBatch(List<AuthorizationRequest> requests) {
        return requests.stream().map(evaluator).toList();
      }
    };
  }
}
