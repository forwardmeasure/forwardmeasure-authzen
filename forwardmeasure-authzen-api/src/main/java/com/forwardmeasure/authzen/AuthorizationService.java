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

import java.util.List;

/**
 * Ported verbatim from forwardmeasure-openworkflow's real {@code AuthorizationService} - the origin
 * of this whole contract, extracted here once forwardmeasure-entity-intelligence's own verbatim
 * port and forwardmeasure-data-streaming's own about-to-be-third-copy made clear this belonged in
 * one shared library, not one per product.
 */
public interface AuthorizationService {
  AuthorizationDecision evaluate(AuthorizationRequest request);

  List<AuthorizationDecision> evaluateBatch(List<AuthorizationRequest> requests);

  default void requireAuthorized(AuthorizationRequest request) {
    if (!evaluate(request).permitted()) {
      throw new AuthorizationDeniedException(request.correlationId());
    }
  }
}
