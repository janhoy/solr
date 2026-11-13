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

package org.apache.solr.shell.exec;

import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import org.apache.solr.cats.exec.ProgramUnderTest;
import org.apache.solr.cats.exec.RunningProgram;
import org.apache.solr.cli.SolrProcessManager;

/**
 * Solr as the program the harness drives: how its nodes are discovered, stopped, and what they
 * leave behind.
 *
 * <p>Discovery is deliberately not done by reading pid files: {@code bin/solr} writes {@code
 * solr-<port>.pid} holding a PID while {@code bin\solr.cmd} writes {@code solr-<port>.port} holding
 * a port. Going through {@link SolrProcessManager}, which resolves either, means one code path for
 * both platforms and finds a node started in the <em>foreground</em>, which writes no file at all.
 *
 * <p>It is scoped by the command-line marker the harness starts its nodes with, so what comes back
 * is the harness' own nodes and never a developer's Solr or another suite's.
 */
public final class SolrProgram implements ProgramUnderTest {

  /**
   * The prefix every harness marker begins with. Discovery matches on a substring, so this finds
   * the harness' nodes from any run, where a full marker only finds one scope's.
   */
  public static final String MARKER_PREFIX = "solr-shell-test-";

  /**
   * The running nodes whose command line contains {@code marker}.
   *
   * <p>Pass a full marker for one scope's nodes, or {@link #MARKER_PREFIX} for every harness node
   * on the host.
   */
  @Override
  public List<RunningProgram> running(String marker) {
    // SolrProcessManager reads the marker from a system property, via EnvUtils, when constructed.
    // Set and restored around the call so the harness JVM is left as it was.
    String previous = System.getProperty(SolrProcessManager.PROCESS_SCAN_MARKER);
    System.setProperty(SolrProcessManager.PROCESS_SCAN_MARKER, marker);
    try {
      SolrProcessManager processes = new SolrProcessManager();
      return processes.getAllRunning().stream()
          .map(node -> new RunningProgram(node.pid(), node.port()))
          .toList();
    } finally {
      if (previous == null) {
        System.clearProperty(SolrProcessManager.PROCESS_SCAN_MARKER);
      } else {
        System.setProperty(SolrProcessManager.PROCESS_SCAN_MARKER, previous);
      }
    }
  }

  @Override
  public Optional<String> stopCommand(int port) {
    return Optional.of("solr stop -p " + port);
  }

  /**
   * Both spellings: {@code bin/solr} writes {@code solr-<port>.pid}, {@code bin\solr.cmd} writes
   * {@code solr-<port>.port}, and {@link SolrProcessManager} reads either. Only a graceful stop
   * removes its own file, so a stale one left by a force-kill is what {@code solr stop --all} and
   * {@code solr status} would later walk.
   */
  @Override
  public List<Path> staleStateFiles(Path stateDir, int port) {
    return List.of(
        stateDir.resolve("solr-" + port + ".pid"), stateDir.resolve("solr-" + port + ".port"));
  }
}
