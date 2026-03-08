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
package org.apache.solr.cloud.kube;

import io.kubernetes.client.openapi.models.V1ConfigMap;
import io.kubernetes.client.openapi.models.V1ObjectMeta;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.apache.solr.SolrTestCase;
import org.apache.solr.core.SolrResourceNotFoundException;
import org.junit.Test;

public class KubernetesSolrResourceLoaderTest extends SolrTestCase {

  private V1ConfigMap makeConfigMap(String configSetName, Map<String, String> data) {
    V1ObjectMeta meta =
        new V1ObjectMeta()
            .putAnnotationsItem(
                KubernetesConfigSetService.CONFIG_SET_NAME_ANNOTATION_KEY, configSetName);
    return new V1ConfigMap().metadata(meta).data(data);
  }

  private KubernetesSolrResourceLoader makeLoader(
      Map<String, V1ConfigMap> cache, String configSetName) {
    return new KubernetesSolrResourceLoader(
        createTempDir(),
        configSetName,
        KubernetesSolrResourceLoaderTest.class.getClassLoader(),
        cache);
  }

  @Test
  public void testOpenResourceFromConfigMap() throws Exception {
    String resource = "solrconfig.xml";
    String content = "<config/>";
    V1ConfigMap cm = makeConfigMap("my-configset", Map.of(resource, content));

    KubernetesSolrResourceLoader loader = makeLoader(Map.of("my-configset", cm), "my-configset");
    try (InputStream is = loader.openResource(resource)) {
      String result = new String(is.readAllBytes(), StandardCharsets.UTF_8);
      assertEquals(content, result);
    }
  }

  @Test
  public void testOpenResourceFallbackToClasspath() throws Exception {
    // ConfigMap exists but does not contain the requested resource
    V1ConfigMap cm = makeConfigMap("my-configset", Map.of("other-file.xml", "data"));

    KubernetesSolrResourceLoader loader = makeLoader(Map.of("my-configset", cm), "my-configset");
    try (InputStream is = loader.openResource("test-classpath-resource.txt")) {
      assertNotNull(is);
      String content = new String(is.readAllBytes(), StandardCharsets.UTF_8);
      assertTrue(content.contains("classpath"));
    }
  }

  @Test
  public void testOpenResourceNotFoundAnywhere() throws Exception {
    // configSet not in cache, resource not on classpath
    KubernetesSolrResourceLoader loader = makeLoader(Map.of(), "my-configset");
    assertThrows(
        SolrResourceNotFoundException.class,
        () -> loader.openResource("absolutely-nonexistent-resource.xml"));
  }

  @Test
  public void testConfigSetNotInCache_fallsBackToClasspath() throws Exception {
    // configSet absent from cache → fall through to classpath
    KubernetesSolrResourceLoader loader = makeLoader(Map.of(), "my-configset");
    try (InputStream is = loader.openResource("test-classpath-resource.txt")) {
      assertNotNull(is);
    }
  }

  @Test
  public void testGetConfigSetName() {
    KubernetesSolrResourceLoader loader = makeLoader(Map.of(), "test-configset");
    assertEquals("test-configset", loader.getConfigSetName());
  }
}
