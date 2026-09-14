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

import com.forwardmeasure.authzen.AuthorizationDecision;
import com.forwardmeasure.authzen.AuthorizationRequest;
import com.forwardmeasure.authzen.AuthorizationService;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Predicate;

/**
 * Explicit test-only PDP stub, ported from forwardmeasure-openworkflow's real {@code
 * StubAuthorizationService}. Its default (bare {@link Predicate} constructor / {@link #denyAll()})
 * is deny, preserving fail-closed test composition; {@link #permitAll()} (new here - none of the
 * three products' own real call sites happened to need it before, but a consumer wiring a
 * happy-path integration test under a test build-profile, per each product's own {@code
 * AuthorizationServiceProducer}, genuinely does) is the one addition to the ported shape.
 */
public final class StubAuthorizationService implements AuthorizationService {
  private final Predicate<AuthorizationRequest> permits;

  public StubAuthorizationService(Predicate<AuthorizationRequest> permits) {
    this.permits = Objects.requireNonNull(permits, "permits");
  }

  public static StubAuthorizationService denyAll() {
    return new StubAuthorizationService(ignored -> false);
  }

  public static StubAuthorizationService permitAll() {
    return new StubAuthorizationService(ignored -> true);
  }

  @Override
  public AuthorizationDecision evaluate(AuthorizationRequest request) {
    return new AuthorizationDecision(
        permits.test(request), request.correlationId(), Map.of("stub", true));
  }

  @Override
  public List<AuthorizationDecision> evaluateBatch(List<AuthorizationRequest> requests) {
    return requests.stream().map(this::evaluate).toList();
  }
}
