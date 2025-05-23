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

package org.apache.solr.client.solrj.impl;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Collection;
import java.util.Map;
import java.util.Set;
import org.apache.solr.client.solrj.ResponseParser;
import org.apache.solr.common.SolrException;
import org.apache.solr.common.util.NamedList;
import org.noggit.JSONParser;
import org.noggit.ObjectBuilder;

/**
 * Parses the input as a JSON {@link Map}, and puts the entries onto the response {@link NamedList}.
 */
public class JsonMapResponseParser extends ResponseParser {
  @Override
  public String getWriterType() {
    return "json";
  }

  @Override
  @SuppressWarnings({"unchecked"})
  public NamedList<Object> processResponse(InputStream body, String encoding) throws IOException {
    @SuppressWarnings({"rawtypes"})
    Map map = null;
    try (InputStreamReader reader =
        new InputStreamReader(body, encoding == null ? "UTF-8" : encoding)) {
      ObjectBuilder builder = new ObjectBuilder(new JSONParser(reader));
      map = (Map) builder.getObject();
    } catch (JSONParser.ParseException e) {
      throw new SolrException(SolrException.ErrorCode.SERVER_ERROR, "JSON parsing error", e);
    }
    NamedList<Object> list = new NamedList<>();
    list.addAll(map);
    return list;
  }

  @Override
  public Collection<String> getContentTypes() {
    return Set.of("application/json");
  }
}
