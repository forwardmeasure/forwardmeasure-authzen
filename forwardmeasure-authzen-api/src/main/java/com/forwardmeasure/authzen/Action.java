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

/**
 * Marker interface for actions that can be authorized - the real, already-proven pattern from
 * data-fabric's own {@code com.forwardmeasure.datafabric.core.domain.authn.Action} (and its {@code
 * CommonAction}/{@code DataPipelineAction}/{@code FileAction}/... implementors), adopted here
 * 2026-09-14 after an earlier version of this library made {@link AuthorizationRequest#action()} a
 * plain {@code String} instead - real type safety at every call site, not scope-string comparisons
 * that only get caught by a compiler if a caller remembers to compare the right kind of value.
 *
 * <p>Each product's own action vocabulary (fowf's real {@code AuthorizationAction} enum, fei's and
 * FDS's own equivalents) implements this directly - {@code enum AuthorizationAction implements
 * Action}. An enum's own {@link Enum#name()} is {@code final} and already satisfies this
 * interface's {@link #name()} requirement with no extra code; only {@link #scope()} needs a real
 * implementation (each enum constant's own AuthZEN wire scope string).
 */
public interface Action {
  /** The real AuthZEN wire scope string (e.g. {@code "human-task:decide"}). */
  String scope();

  /** The action's own symbolic name - every {@code enum} already provides this via {@link Enum}. */
  String name();

  /**
   * Whether this action implies {@code other} being permitted too (e.g. an {@code ADMIN} action
   * implying {@code UPDATE}/{@code DELETE}). Default: an action only implies itself - override for
   * a real hierarchy, matching data-fabric's own {@code Action} default.
   */
  default boolean implies(Action other) {
    return this.equals(other);
  }
}
