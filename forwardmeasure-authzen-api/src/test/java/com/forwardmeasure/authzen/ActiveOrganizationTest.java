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
package com.forwardmeasure.authzen;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.forwardmeasure.jpa.tenancy.TenantDatabase;
import com.forwardmeasure.jpa.tenancy.TenantId;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/** Ported verbatim from forwardmeasure-openworkflow's real {@code ActiveOrganizationTest}. */
class ActiveOrganizationTest {
  private static final TenantDatabase DATABASE = TenantDatabase.forAlias("activeorganizationtest");

  @Test
  void activeOrganizationIsPartOfTheAuthorizationIdentity() {
    TenantId tenant = new TenantId(UUID.randomUUID());
    ActiveOrganization first =
        new ActiveOrganization(tenant, DATABASE, "org-a", "actor", Set.of("workflow-author"));
    ActiveOrganization second =
        new ActiveOrganization(tenant, DATABASE, "org-b", "actor", Set.of("workflow-author"));
    assertNotEquals(first, second);
  }

  @Test
  void missingActiveOrganizationDataIsRejected() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new ActiveOrganization(
                new TenantId(UUID.randomUUID()), DATABASE, "", "actor", Set.of()));
  }
}
