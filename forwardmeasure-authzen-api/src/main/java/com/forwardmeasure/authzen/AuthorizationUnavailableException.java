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
 * The PDP could not be reached or did not answer usably - a non-200 response, malformed JSON, a
 * network error, or a correlation-id echo mismatch. Fail-closed: this is thrown, never silently
 * treated as permit.
 */
public final class AuthorizationUnavailableException extends RuntimeException {
  private static final long serialVersionUID = 1L;

  public AuthorizationUnavailableException(String message) {
    super(message);
  }

  public AuthorizationUnavailableException(String message, Throwable cause) {
    super(message, cause);
  }
}
