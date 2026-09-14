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
 * The generic {@code (type, id, properties)} shape every product's own real {@code
 * AuthorizationResource} (fowf's {@code definition(id)}/{@code execution(id)}/..., fei's {@code
 * referencePopulation(id)}/{@code entity(id)}/..., FDS's {@code ingestionRun(id)}/...) already used
 * underneath its own static factory methods. Those factory methods stay local to each product -
 * they're domain vocabulary, not shared transport - so this shared type carries only the
 * constructor they all already called.
 */
public record AuthorizationResource(String type, String id, Map<String, Object> properties) {
  public AuthorizationResource {
    type = requireText(type, "type");
    id = requireText(id, "id");
    properties = Map.copyOf(Objects.requireNonNull(properties, "properties"));
  }

  private static String requireText(String value, String name) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException(name + " must not be blank");
    }
    return value;
  }
}
