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

import com.forwardmeasure.jpa.tenancy.TenantDatabase;
import com.forwardmeasure.jpa.tenancy.TenantId;
import java.util.Objects;
import java.util.Set;

/**
 * Trusted identity extracted from one explicitly active Keycloak Organization. Ported verbatim from
 * forwardmeasure-openworkflow's real {@code ActiveOrganization}, then extended with {@link
 * #tenantDatabase()} - the Organization's own alias (the JWT {@code organization} claim's map key)
 * is already available at extraction time (see {@code KeycloakOrganizationClaims#extract}), so
 * request-scoped call sites can resolve {@code TenantScope}'s real routing target directly, with no
 * separate registry lookup.
 */
public record ActiveOrganization(
    TenantId tenantId,
    TenantDatabase tenantDatabase,
    String organizationId,
    String actorId,
    Set<String> organizationRoles) {
  public ActiveOrganization {
    Objects.requireNonNull(tenantId, "tenantId");
    Objects.requireNonNull(tenantDatabase, "tenantDatabase");
    organizationId = requireText(organizationId, "organizationId");
    actorId = requireText(actorId, "actorId");
    organizationRoles = Set.copyOf(Objects.requireNonNull(organizationRoles, "organizationRoles"));
  }

  private static String requireText(String value, String name) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException(name + " must not be blank");
    }
    return value;
  }
}
