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
package org.apache.solr.schema;

import java.util.HashMap;
import java.util.Map;
import org.apache.lucene.util.ResourceLoader;
import org.apache.solr.SolrTestCaseJ4;
import org.apache.solr.common.SolrException;
import org.apache.solr.common.util.SuppressForbidden;
import org.apache.solr.core.SolrResourceLoader;
import org.junit.Before;
import org.junit.Test;

/** Tests currency field type. */
public class OpenExchangeRatesOrgProviderTest extends SolrTestCaseJ4 {
  private static final long HARDCODED_TEST_TIMESTAMP = 1332070464L;

  OpenExchangeRatesOrgProvider oerp;
  ResourceLoader loader;
  private final Map<String, String> mockParams = new HashMap<>();

  @Override
  @Before
  public void setUp() throws Exception {
    CurrencyFieldTypeTest.assumeCurrencySupport("USD", "EUR", "MXN", "GBP", "JPY");

    super.setUp();
    mockParams.put(
        OpenExchangeRatesOrgProvider.PARAM_RATES_FILE_LOCATION, "open-exchange-rates.json");
    oerp = new OpenExchangeRatesOrgProvider();
    loader = new SolrResourceLoader(TEST_PATH().resolve("collection1"));
  }

  @Test
  public void testInit() {
    oerp.init(mockParams);
    // don't inform, we don't want to hit any of these URLs

    assertEquals("Wrong url", "open-exchange-rates.json", oerp.ratesFileLocation);
    assertEquals("Wrong default interval", (1440 * 60), oerp.refreshIntervalSeconds);

    Map<String, String> params = new HashMap<>();
    params.put(OpenExchangeRatesOrgProvider.PARAM_RATES_FILE_LOCATION, "http://foo.bar/baz");
    params.put(OpenExchangeRatesOrgProvider.PARAM_REFRESH_INTERVAL, "100");

    oerp.init(params);
    assertEquals("Wrong param set url", "http://foo.bar/baz", oerp.ratesFileLocation);
    assertEquals("Wrong param interval", (100 * 60), oerp.refreshIntervalSeconds);
  }

  @Test
  public void testList() {
    oerp.init(mockParams);
    oerp.inform(loader);
    assertEquals(5, oerp.listAvailableCurrencies().size());
  }

  @Test
  public void testGetExchangeRate() {
    oerp.init(mockParams);
    oerp.inform(loader);
    assertEquals(81.29D, oerp.getExchangeRate("USD", "JPY"), 0.0D);
    assertEquals("USD", oerp.rates.getBaseCurrency());
  }

  @SuppressForbidden(reason = "Needs currentTimeMillis to construct rates file contents")
  @Test
  public void testReload() {
    // reminder: interval is in minutes
    mockParams.put(OpenExchangeRatesOrgProvider.PARAM_REFRESH_INTERVAL, "100");
    oerp.init(mockParams);
    oerp.inform(loader);

    // reminder: timestamp is in seconds
    assertEquals(HARDCODED_TEST_TIMESTAMP, oerp.rates.getTimestamp());

    // modify the timestamp to be "current" then fetch a rate and ensure no reload
    final long currentTimestamp = System.currentTimeMillis() / 1000;
    oerp.rates.setTimestamp(currentTimestamp);
    assertEquals(81.29D, oerp.getExchangeRate("USD", "JPY"), 0.0D);
    assertEquals(currentTimestamp, oerp.rates.getTimestamp());

    // roll back clock on timestamp and ensure rate fetch does reload
    oerp.rates.setTimestamp(currentTimestamp - (101 * 60));
    assertEquals(81.29D, oerp.getExchangeRate("USD", "JPY"), 0.0D);
    assertEquals(
        "timestamp wasn't reset to hardcoded value, indicating no reload",
        HARDCODED_TEST_TIMESTAMP,
        oerp.rates.getTimestamp());
  }

  @Test(expected = SolrException.class)
  public void testNoInit() {
    oerp.getExchangeRate("ABC", "DEF");
    fail("Should have thrown exception if not initialized");
  }

  @Test
  public void testUrlSecurityValidation_HttpsAllowed() {
    // HTTPS URLs with correct domain should pass validation
    oerp.init(mockParams);
    Map<String, String> params = new HashMap<>();
    params.put(
        OpenExchangeRatesOrgProvider.PARAM_RATES_FILE_LOCATION,
        "https://openexchangerates.org/api/latest.json");
    params.put(OpenExchangeRatesOrgProvider.PARAM_REFRESH_INTERVAL, "1440");
    oerp.init(params);
    assertEquals(
        "https://openexchangerates.org/api/latest.json", oerp.ratesFileLocation);
    // Note: We don't call inform() to avoid actually fetching the URL
  }

  @Test
  public void testUrlSecurityValidation_HttpBlocked() {
    // HTTP URLs should be rejected for security
    try {
      Map<String, String> params = new HashMap<>();
      params.put(
          OpenExchangeRatesOrgProvider.PARAM_RATES_FILE_LOCATION,
          "http://openexchangerates.org/api/latest.json");
      params.put(OpenExchangeRatesOrgProvider.PARAM_REFRESH_INTERVAL, "1440");
      oerp.init(params);
      oerp.inform(loader);
      fail("Should have thrown exception for HTTP URL");
    } catch (SolrException e) {
      assertTrue("Should mention HTTPS requirement", e.getMessage().contains("HTTPS"));
    }
  }

  @Test
  public void testUrlSecurityValidation_FileSchemeBlocked() {
    // file:// URLs should be rejected
    try {
      Map<String, String> params = new HashMap<>();
      params.put(
          OpenExchangeRatesOrgProvider.PARAM_RATES_FILE_LOCATION, "file:///etc/passwd");
      params.put(OpenExchangeRatesOrgProvider.PARAM_REFRESH_INTERVAL, "1440");
      oerp.init(params);
      oerp.inform(loader);
      fail("Should have thrown exception for file:// URL");
    } catch (SolrException e) {
      assertTrue("Should mention HTTPS requirement", e.getMessage().contains("HTTPS"));
    }
  }

  @Test
  public void testUrlSecurityValidation_WrongPathBlocked() {
    // HTTPS URLs with wrong path should be rejected
    try {
      Map<String, String> params = new HashMap<>();
      params.put(
          OpenExchangeRatesOrgProvider.PARAM_RATES_FILE_LOCATION,
          "https://example.com/api/rates.json");
      params.put(OpenExchangeRatesOrgProvider.PARAM_REFRESH_INTERVAL, "1440");
      oerp.init(params);
      oerp.inform(loader);
      fail("Should have thrown exception for path not ending in /latest.json");
    } catch (SolrException e) {
      assertTrue(
          "Should mention /latest.json requirement",
          e.getMessage().contains("/latest.json"));
    }
  }

  @Test
  public void testUrlSecurityValidation_LocalFilePathAllowed() {
    // Local file paths (without scheme) should be allowed
    oerp.init(mockParams);
    oerp.inform(loader);
    assertEquals(5, oerp.listAvailableCurrencies().size());
  }

  @Test
  public void testUrlSecurityValidation_JarSchemeBlocked() {
    // jar:// URLs should be rejected
    try {
      Map<String, String> params = new HashMap<>();
      params.put(
          OpenExchangeRatesOrgProvider.PARAM_RATES_FILE_LOCATION,
          "jar:file:///path/to/file.jar!/resource");
      params.put(OpenExchangeRatesOrgProvider.PARAM_REFRESH_INTERVAL, "1440");
      oerp.init(params);
      oerp.inform(loader);
      fail("Should have thrown exception for jar:// URL");
    } catch (SolrException e) {
      assertTrue("Should mention HTTPS requirement", e.getMessage().contains("HTTPS"));
    }
  }

  @Test
  public void testUrlSecurityValidation_NoSchemeAllowed() {
    // URLs without scheme (local paths) should be allowed and use ResourceLoader
    Map<String, String> params = new HashMap<>();
    params.put(
        OpenExchangeRatesOrgProvider.PARAM_RATES_FILE_LOCATION, "open-exchange-rates.json");
    oerp.init(params);
    assertEquals("open-exchange-rates.json", oerp.ratesFileLocation);
    // Inform should succeed with local file
    oerp.inform(loader);
    assertEquals(5, oerp.listAvailableCurrencies().size());
  }

  @Test
  public void testUrlSecurityValidation_AnyDomainAllowed() {
    // HTTPS URLs with correct path ending should be allowed from any domain
    oerp.init(mockParams);
    Map<String, String> params = new HashMap<>();
    params.put(
        OpenExchangeRatesOrgProvider.PARAM_RATES_FILE_LOCATION,
        "https://custom-service.example.com/api/latest.json");
    params.put(OpenExchangeRatesOrgProvider.PARAM_REFRESH_INTERVAL, "1440");
    oerp.init(params);
    assertEquals(
        "https://custom-service.example.com/api/latest.json", oerp.ratesFileLocation);
    // Note: We don't call inform() to avoid actually fetching the URL
  }
}
