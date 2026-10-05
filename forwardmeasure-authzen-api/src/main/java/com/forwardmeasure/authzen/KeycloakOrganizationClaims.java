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

import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Fail-closed extraction of one active Keycloak 26.7 Organization and its nested client roles.
 * Ported from forwardmeasure-openworkflow's real {@code KeycloakOrganizationClaims} - same claims
 * shape, same fail-closed checks - with one deliberate change: every failure throws {@link
 * AuthenticationRequiredException} instead of the origin's {@code SecurityException}. See that
 * exception's own javadoc for why.
 */
public final class KeycloakOrganizationClaims {
  private static final String TENANT_DID_ATTRIBUTE = "forwardmeasure.tenant-did";

  private KeycloakOrganizationClaims() {}

  public static ActiveOrganization extract(Map<String, ?> claims, String clientId) {
    Object subject = claims.get("sub");
    if (!(subject instanceof String actorId) || actorId.isBlank()) {
      throw new AuthenticationRequiredException("JWT subject is required");
    }
    Map<?, ?> organizations = map(claims.get("organization"), "organization");
    if (organizations.size() != 1) {
      throw new AuthenticationRequiredException("JWT must contain exactly one active Organization");
    }
    Map.Entry<?, ?> selected = organizations.entrySet().iterator().next();
    if (!(selected.getKey() instanceof String alias) || alias.isBlank()) {
      throw new AuthenticationRequiredException("Active Organization alias is invalid");
    }
    Map<?, ?> organization = map(selected.getValue(), "active Organization");
    Object id = organization.get("id");
    if (!(id instanceof String organizationId) || organizationId.isBlank()) {
      throw new AuthenticationRequiredException("Active Organization id is required");
    }
    String tenantDid = singletonText(organization.get(TENANT_DID_ATTRIBUTE), TENANT_DID_ATTRIBUTE);
    Set<String> organizationRoles =
        organizationRoles(organization.get("resource_access"), clientId);
    try {
      return new ActiveOrganization(
          com.forwardmeasure.jpa.tenancy.TenantId.forDid(
              com.forwardmeasure.jpa.tenancy.Did.parse(tenantDid)),
          organizationId,
          actorId,
          organizationRoles);
    } catch (IllegalArgumentException failure) {
      throw new AuthenticationRequiredException(
          "Active Organization tenant DID is invalid", failure);
    }
  }

  /**
   * The active Organization's roles for {@code clientId}. Keycloak omits the Organization's
   * resource_access (or this client's entry) for a member who holds no role there; that member is
   * authenticated with no roles, so authorization denies them (403) instead of authentication
   * failing (401). A claim that is present but malformed is still rejected.
   */
  private static Set<String> organizationRoles(Object resourceAccess, String clientId) {
    if (resourceAccess == null) {
      return Set.of();
    }
    Object clientValue = map(resourceAccess, "Organization resource_access").get(clientId);
    if (clientValue == null) {
      return Set.of();
    }
    Object rolesValue = map(clientValue, "Organization client roles").get("roles");
    if (!(rolesValue instanceof Collection<?> roles)) {
      throw new AuthenticationRequiredException("Active Organization client roles are required");
    }
    return roles.stream()
        .map(KeycloakOrganizationClaims::role)
        .collect(Collectors.toUnmodifiableSet());
  }

  private static Map<?, ?> map(Object value, String name) {
    if (!(value instanceof Map<?, ?> map)) {
      throw new AuthenticationRequiredException(name + " claim is required");
    }
    return map;
  }

  private static String role(Object value) {
    if (!(value instanceof String role) || role.isBlank()) {
      throw new AuthenticationRequiredException("Organization role must be text");
    }
    return role;
  }

  private static String singletonText(Object value, String name) {
    Object selected = value;
    if (value instanceof Collection<?> values) {
      if (values.size() != 1) {
        throw new AuthenticationRequiredException(name + " must contain exactly one value");
      }
      selected = values.iterator().next();
    }
    if (!(selected instanceof String text) || text.isBlank()) {
      throw new AuthenticationRequiredException(name + " is required");
    }
    return text;
  }
}
