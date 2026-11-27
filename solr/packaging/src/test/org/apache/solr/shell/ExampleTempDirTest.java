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

package org.apache.solr.shell;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.Test;

/**
 * An example started without {@code --solr-home} keeps its Solr home and logs under {@code
 * solr-example/<example>} in the temp directory, out of the installation.
 */
public class ExampleTempDirTest extends SolrCatsTestCase {

  @Test
  public void exampleDefaultsToTheTempDirectory() {
    Path tmp = mkdirs("tmp");
    // bin/solr hands TMPDIR to the example tool as java.io.tmpdir; on Windows Java reads TMP/TEMP
    env("TMPDIR", tmp.toString());
    env("TMP", tmp.toString());
    env("TEMP", tmp.toString());
    // the harness sets a logs directory for every test, and a caller's setting wins
    env("SOLR_LOGS_DIR", "");

    run("solr start -e techproducts --no-prompt -p ${SOLR_PORT}");
    run("solr assert --started http://localhost:${SOLR_PORT} --timeout 10000");

    Path exampleDir = tmp.resolve("solr-example").resolve("techproducts");
    assertTrue(Files.isRegularFile(exampleDir.resolve("solr").resolve("solr.xml")));
    assertTrue(Files.isRegularFile(exampleDir.resolve("logs").resolve("solr.log")));
    assertFalse(
        Files.exists(
            harnessEnv.solrTip().resolve("server").resolve("solr").resolve("techproducts")));
  }
}
