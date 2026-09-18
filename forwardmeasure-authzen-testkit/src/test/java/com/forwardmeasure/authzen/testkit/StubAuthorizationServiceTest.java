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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.forwardmeasure.authzen.Action;
import com.forwardmeasure.authzen.ActiveOrganization;
import com.forwardmeasure.authzen.AuthorizationDeniedException;
import com.forwardmeasure.authzen.AuthorizationRequest;
import com.forwardmeasure.authzen.AuthorizationResource;
import com.forwardmeasure.jpa.tenancy.TenantDatabase;
import com.forwardmeasure.jpa.tenancy.TenantId;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class StubAuthorizationServiceTest {
  /** A minimal, real {@link Action} implementor - the shape every product's own enum matches. */
  private enum TestAction implements Action {
    READ("widget:read");

    private final String scope;

    TestAction(String scope) {
      this.scope = scope;
    }

    @Override
    public String scope() {
      return scope;
    }
  }

  private static final AuthorizationRequest REQUEST =
      new AuthorizationRequest(
          new ActiveOrganization(
              new TenantId(UUID.randomUUID()),
              TenantDatabase.forAlias("stubauthorizationservicetest"),
              "org-1",
              "actor-1",
              Set.of("reviewer")),
          new AuthorizationResource("widget", "widgets", Map.of()),
          TestAction.READ,
          "correlation-1",
          Map.of());

  @Test
  void permitAllAlwaysPermits() {
    assertTrue(StubAuthorizationService.permitAll().evaluate(REQUEST).permitted());
    StubAuthorizationService.permitAll().requireAuthorized(REQUEST);
  }

  @Test
  void denyAllAlwaysDeniesAndFailsFastOnRequireAuthorized() {
    assertFalse(StubAuthorizationService.denyAll().evaluate(REQUEST).permitted());
    assertThrows(
        AuthorizationDeniedException.class,
        () -> StubAuthorizationService.denyAll().requireAuthorized(REQUEST));
  }
}
