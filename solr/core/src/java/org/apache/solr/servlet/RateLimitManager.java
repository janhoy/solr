/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.solr.servlet;

import static org.apache.solr.common.params.CommonParams.SOLR_REQUEST_CONTEXT_PARAM;
import static org.apache.solr.common.params.CommonParams.SOLR_REQUEST_TYPE_PARAM;

import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.lang.invoke.MethodHandles;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import net.jcip.annotations.ThreadSafe;
import org.apache.solr.client.solrj.SolrRequest;
import org.apache.solr.common.cloud.ClusterPropertiesListener;
import org.apache.solr.common.cloud.SolrZkClient;
import org.apache.solr.core.RateLimiterConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class is responsible for managing rate limiting per request type. Rate limiters can be
 * registered with this class against a corresponding type. There can be only one rate limiter
 * associated with a request type.
 *
 * <p>The actual rate limiting and the limits should be implemented in the corresponding
 * RequestRateLimiter implementation. RateLimitManager is responsible for the orchestration but not
 * the specifics of how the rate limiting is being done for a specific request type.
 */
@ThreadSafe
public class RateLimitManager implements ClusterPropertiesListener {
  private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

  public static final String ERROR_MESSAGE =
      "Too many requests for this request type. Please try after some time or increase the quota for this request type";
  public static final int DEFAULT_CONCURRENT_REQUESTS =
      (Runtime.getRuntime().availableProcessors()) * 3;
  public static final long DEFAULT_SLOT_ACQUISITION_TIMEOUT_MS = -1;
  private final ConcurrentHashMap<String, RequestRateLimiter> requestRateLimiterMap;

  public RateLimitManager() {
    this.requestRateLimiterMap = new ConcurrentHashMap<>();
  }

  @Override
  public boolean onChange(Map<String, Object> properties) {

    // Hack: We only support query rate limiting for now
    requestRateLimiterMap.compute(
        SolrRequest.SolrRequestType.QUERY.toString(),
        (k, v) -> {
          try {
            RateLimiterConfig newConfig =
                QueryRateLimiter.processConfigChange(
                    SolrRequest.SolrRequestType.QUERY,
                    v == null ? null : v.getRateLimiterConfig(),
                    properties);
            if (newConfig == null) {
              return v;
            } else {
              return new QueryRateLimiter(newConfig);
            }
          } catch (IOException e) {
            throw new UncheckedIOException(e);
          }
        });

    return false;
  }

  // Handles an incoming request. The main orchestration code path, this method will
  // identify which (if any) rate limiter can handle this request. Internal requests will not be
  // rate limited
  // Returns true if request is accepted for processing, false if it should be rejected
  public RequestRateLimiter.SlotReservation handleRequest(HttpServletRequest request)
      throws InterruptedException {
    String requestContext = request.getHeader(SOLR_REQUEST_CONTEXT_PARAM);
    String typeOfRequest = request.getHeader(SOLR_REQUEST_TYPE_PARAM);

    if (typeOfRequest == null) {
      // Cannot determine if this request should be throttled
      return RequestRateLimiter.UNLIMITED;
    }

    // Do not throttle internal requests
    if (requestContext != null
        && requestContext.equals(SolrRequest.SolrClientContext.SERVER.toString())) {
      return RequestRateLimiter.UNLIMITED;
    }

    RequestRateLimiter requestRateLimiter = requestRateLimiterMap.get(typeOfRequest);

    if (requestRateLimiter == null) {
      // No request rate limiter for this request type
      return RequestRateLimiter.UNLIMITED;
    }

    // slot borrowing should be fallback behavior, so if `slotAcquisitionTimeoutInMS`
    // is configured it will be applied here (blocking if necessary), to make a best
    // effort to draw from the request's own slot pool.
    RequestRateLimiter.SlotReservation result = requestRateLimiter.handleRequest();

    if (result != null) {
      return result;
    }

    return trySlotBorrowing(typeOfRequest); // possibly null, if unable to borrow a slot
  }

  /* For a rejected request type, do the following:
   * For each request rate limiter whose type that is not of the type of the request which got rejected,
   * check if slot borrowing is enabled. If enabled, try to acquire a slot.
   * If allotted, return else try next request type.
   *
   * @lucene.experimental -- Can cause slots to be blocked if a request borrows a slot and is itself long lived.
   */
  private RequestRateLimiter.SlotReservation trySlotBorrowing(String requestType) {
    // TODO: randomly distributed slot borrowing over available RequestRateLimiters
    for (Map.Entry<String, RequestRateLimiter> currentEntry : requestRateLimiterMap.entrySet()) {
      RequestRateLimiter.SlotReservation result = null;
      RequestRateLimiter requestRateLimiter = currentEntry.getValue();

      // Cant borrow from ourselves
      if (requestRateLimiter.getRateLimiterConfig().requestType.toString().equals(requestType)) {
        continue;
      }

      if (requestRateLimiter.getRateLimiterConfig().isSlotBorrowingEnabled) {
        if (log.isWarnEnabled()) {
          String msg =
              "WARN: Experimental feature slots borrowing is enabled for request rate limiter type "
                  + requestRateLimiter.getRateLimiterConfig().requestType.toString();

          log.warn(msg);
        }

        try {
          result = requestRateLimiter.allowSlotBorrowing();
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
        }

        if (result != null) {
          return result;
        }
      }
    }

    return null;
  }

  public void registerRequestRateLimiter(
      RequestRateLimiter requestRateLimiter, SolrRequest.SolrRequestType requestType) {
    requestRateLimiterMap.put(requestType.toString(), requestRateLimiter);
  }

  public RequestRateLimiter getRequestRateLimiter(SolrRequest.SolrRequestType requestType) {
    return requestRateLimiterMap.get(requestType.toString());
  }

  public static class Builder {
    protected SolrZkClient solrZkClient;

    public Builder(SolrZkClient solrZkClient) {
      this.solrZkClient = solrZkClient;
    }

    public RateLimitManager build() {
      RateLimitManager rateLimitManager = new RateLimitManager();

      rateLimitManager.registerRequestRateLimiter(
          new QueryRateLimiter(solrZkClient), SolrRequest.SolrRequestType.QUERY);

      return rateLimitManager;
    }
  }
}
