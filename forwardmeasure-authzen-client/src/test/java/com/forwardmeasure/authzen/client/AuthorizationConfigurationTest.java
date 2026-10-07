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

import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import org.junit.jupiter.api.Test;

class AuthorizationConfigurationTest {
  private static final URI ENDPOINT = URI.create("http://127.0.0.1:1/unreachable");

  @Test
  void invalidTimeoutAndCacheBoundsCannotCreateAnAuthorizationService() {
    for (Duration invalid : new Duration[] {Duration.ZERO, Duration.ofSeconds(-1)}) {
      assertThrows(
          IllegalArgumentException.class,
          () ->
              new AuthzenConfiguration(
                  ENDPOINT, ENDPOINT, invalid, Duration.ofSeconds(30), 1, "policy-v1"));
      assertThrows(
          IllegalArgumentException.class,
          () ->
              new AuthzenConfiguration(
                  ENDPOINT, ENDPOINT, Duration.ofSeconds(2), invalid, 1, "policy-v1"));
    }
    for (int invalid : new int[] {0, -1}) {
      assertThrows(
          IllegalArgumentException.class,
          () ->
              new AuthzenConfiguration(
                  ENDPOINT,
                  ENDPOINT,
                  Duration.ofSeconds(2),
                  Duration.ofSeconds(30),
                  invalid,
                  "policy-v1"));
    }
    for (String invalid : new String[] {null, "", "  "}) {
      assertThrows(
          IllegalArgumentException.class,
          () ->
              new AuthzenConfiguration(
                  ENDPOINT, ENDPOINT, Duration.ofSeconds(2), Duration.ofSeconds(30), 1, invalid));
    }
  }

  @Test
  void missingServiceAccountCredentialsAreRejectedBeforeAnyNetworkRequest() {
    try (var http = HttpClient.newHttpClient()) {
      for (String invalid : new String[] {null, "", "  "}) {
        assertThrows(
            IllegalArgumentException.class,
            () ->
                new OAuthClientCredentialsTokenSupplier(
                    http,
                    new ObjectMapper(),
                    ENDPOINT,
                    invalid,
                    "fixture-secret",
                    Duration.ofSeconds(2)));
        assertThrows(
            IllegalArgumentException.class,
            () ->
                new OAuthClientCredentialsTokenSupplier(
                    http,
                    new ObjectMapper(),
                    ENDPOINT,
                    "fixture-client",
                    invalid,
                    Duration.ofSeconds(2)));
      }
    }
  }
}
