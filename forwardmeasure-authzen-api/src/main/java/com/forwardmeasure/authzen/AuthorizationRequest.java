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

import java.util.Map;
import java.util.Objects;

/**
 * {@code action} is a real, typed {@link Action} - each product's own action vocabulary (fowf's
 * real {@code AuthorizationAction} enum, fei's and FDS's own equivalents) implements that marker
 * interface directly, matching the real, already-proven pattern from data-fabric's own {@code
 * com.forwardmeasure.datafabric.core.domain.authn.Action}.
 *
 * <p><b>Correction, 2026-09-14, later the same day</b>: this field was originally a plain {@code
 * String} (the pre-resolved AuthZEN wire scope) - real type safety was traded away for one fewer
 * layer of indirection. That traded away exactly the thing an enum-based type gives every call site
 * for free: the compiler catching a wrong action at the call site, not a runtime string mismatch.
 * {@link Action} restores that without reintroducing the original problem (the shared library still
 * can't depend on any one product's own enum) - the interface is generic, each product's own enum
 * implements it, and {@code AuthzenAuthorizationService} (in the sibling {@code
 * forwardmeasure-authzen-client} module - the one place that genuinely needs the wire string) calls
 * {@code action.scope()} itself. A product needing dynamic, runtime-resolved action values beyond a
 * fixed enum constant (e.g. fowf's own Human Task disposition-code suffixing) supplies its own
 * small {@link Action} implementation for that one case, rather than this type falling back to an
 * untyped {@code String} for everyone.
 */
public record AuthorizationRequest(
    ActiveOrganization organization,
    AuthorizationResource resource,
    Action action,
    String correlationId,
    Map<String, Object> context) {
  public AuthorizationRequest {
    Objects.requireNonNull(organization, "organization");
    Objects.requireNonNull(resource, "resource");
    Objects.requireNonNull(action, "action");
    if (correlationId == null || correlationId.isBlank()) {
      throw new IllegalArgumentException("correlationId must not be blank");
    }
    context = Map.copyOf(Objects.requireNonNull(context, "context"));
  }
}
