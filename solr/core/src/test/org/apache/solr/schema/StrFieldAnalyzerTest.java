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

import java.io.IOException;
import org.apache.lucene.analysis.Analyzer;
import org.apache.lucene.analysis.BaseTokenStreamTestCase;

public class StrFieldAnalyzerTest extends BaseTokenStreamTestCase {
  public void testOffsetSanity() throws IOException {
    Analyzer analyzer = new StrField().getIndexAnalyzer();
    assertTokenStreamContents(
        analyzer.tokenStream("fieldName", "abc"),
        new String[] {"abc"},
        new int[] {0},
        new int[] {3},
        new int[] {1},
        new int[] {1},
        3);
  }
}