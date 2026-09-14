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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Not a port - the origin's own {@code AuthorizationResourceTest} exercises its own static factory
 * methods ({@code eventTarget()}, {@code schedule(id)}, ...), which are product-specific vocabulary
 * that deliberately does not live in this shared library (see {@link AuthorizationResource}'s own
 * javadoc). This tests what the shared record itself is responsible for: the constructor a
 * product's own factories all call through to.
 */
class AuthorizationResourceTest {
  @Test
  void carriesTypeIdAndProperties() {
    AuthorizationResource resource =
        new AuthorizationResource("widget", "widgets", Map.of("widget_id", "w-1"));
    assertEquals("widget", resource.type());
    assertEquals("widgets", resource.id());
    assertEquals(Map.of("widget_id", "w-1"), resource.properties());
  }

  @Test
  void rejectsABlankTypeOrId() {
    assertThrows(
        IllegalArgumentException.class, () -> new AuthorizationResource("", "widgets", Map.of()));
    assertThrows(
        IllegalArgumentException.class, () -> new AuthorizationResource("widget", "", Map.of()));
  }

  @Test
  void rejectsNullProperties() {
    assertThrows(
        NullPointerException.class, () -> new AuthorizationResource("widget", "widgets", null));
  }

  @Test
  void distinctIdsProduceDistinctResources() {
    assertNotEquals(
        new AuthorizationResource("widget", "widgets", Map.of("widget_id", "a")),
        new AuthorizationResource("widget", "widgets", Map.of("widget_id", "b")));
  }
}
