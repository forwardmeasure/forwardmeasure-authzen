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
package com.forwardmeasure.authzen.client;

import java.net.URI;
import java.time.Duration;
import java.util.Objects;

/** Ported verbatim from forwardmeasure-openworkflow's real {@code AuthzenConfiguration}. */
public record AuthzenConfiguration(
    URI evaluationEndpoint,
    URI evaluationsEndpoint,
    Duration requestTimeout,
    Duration decisionTtl,
    int maximumCacheEntries,
    String policyVersion) {
  public AuthzenConfiguration {
    Objects.requireNonNull(evaluationEndpoint, "evaluationEndpoint");
    Objects.requireNonNull(evaluationsEndpoint, "evaluationsEndpoint");
    positive(requestTimeout, "requestTimeout");
    positive(decisionTtl, "decisionTtl");
    if (maximumCacheEntries < 1) {
      throw new IllegalArgumentException("maximumCacheEntries must be positive");
    }
    if (policyVersion == null || policyVersion.isBlank()) {
      throw new IllegalArgumentException("policyVersion must not be blank");
    }
  }

  private static void positive(Duration value, String name) {
    Objects.requireNonNull(value, name);
    if (value.isZero() || value.isNegative()) {
      throw new IllegalArgumentException(name + " must be positive");
    }
  }
}
