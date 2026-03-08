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
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Map;
import org.apache.solr.core.SolrResourceLoader;
import org.apache.solr.core.SolrResourceNotFoundException;

/**
 * ResourceLoader that works with Kubernetes ConfigMaps.
 *
 * <p>This loader attempts to load resources from a Kubernetes ConfigMap corresponding to the
 * configured configSet. If a resource is not found in the ConfigMap, it falls back to the classpath
 * loader.
 *
 * <p>Resources are served from the live ConfigMap cache maintained by {@link
 * KubernetesConfigSetService}. The cache is kept up to date by a Kubernetes informer, so every call
 * to {@link #openResource(String)} reflects the current state of the ConfigMap without making an
 * API round-trip.
 */
public class KubernetesSolrResourceLoader extends SolrResourceLoader {

  private final String configSetName;
  private final Map<String, V1ConfigMap> configMapCache;

  /**
   * Creates a new KubernetesSolrResourceLoader.
   *
   * <p>This loader will first attempt to load resources from the provided ConfigMap cache. If not
   * found, it will delegate to the context classloader.
   *
   * @param instanceDir the instance directory for the core
   * @param configSetName the name of the configSet (used to look up the ConfigMap in the cache)
   * @param parent the parent classloader
   * @param configMapCache the live ConfigMap cache (keyed by configSet name), kept up to date by
   *     the Kubernetes informer in {@link KubernetesConfigSetService}
   */
  public KubernetesSolrResourceLoader(
      Path instanceDir,
      String configSetName,
      ClassLoader parent,
      Map<String, V1ConfigMap> configMapCache) {
    super(instanceDir, parent);
    this.configSetName = configSetName;
    this.configMapCache = configMapCache;
  }

  /**
   * Opens any resource by its name. First attempts to load the resource from the cached Kubernetes
   * ConfigMap for the configSet. If not found, delegates to the parent classloader.
   *
   * @return the stream for the named resource
   */
  @Override
  public InputStream openResource(String resource) throws IOException {
    V1ConfigMap configMap = configMapCache.get(configSetName);
    if (configMap != null && configMap.getData() != null) {
      String data = configMap.getData().get(resource);
      if (data != null) {
        return new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8));
      }
    }

    // Fall back to the classpath loader
    InputStream is;
    try {
      is = classLoader.getResourceAsStream(resource.replace('\\', '/'));
    } catch (Exception e) {
      throw new IOException("Error opening " + resource, e);
    }
    if (is == null) {
      throw new SolrResourceNotFoundException(
          "Can't find resource '"
              + resource
              + "' in classpath or in Kubernetes ConfigMap '"
              + configSetName
              + "', cwd="
              + System.getProperty("user.dir"));
    }
    return is;
  }

  public String getConfigSetName() {
    return configSetName;
  }
}
