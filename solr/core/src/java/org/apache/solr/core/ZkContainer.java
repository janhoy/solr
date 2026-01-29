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
package org.apache.solr.core;

import static org.apache.solr.common.cloud.ZkStateReader.HTTPS;
import static org.apache.solr.common.cloud.ZkStateReader.HTTPS_PORT_PROP;

import io.opentelemetry.api.common.Attributes;
import java.io.FileReader;
import java.io.IOException;
import java.lang.invoke.MethodHandles;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeoutException;
import java.util.function.Predicate;
import org.apache.solr.client.solrj.impl.SolrZkClientTimeout;
import org.apache.solr.cloud.SolrZkServer;
import org.apache.solr.cloud.ZkController;
import org.apache.solr.common.SolrException;
import org.apache.solr.common.cloud.ClusterProperties;
import org.apache.solr.common.cloud.Replica;
import org.apache.solr.common.cloud.ZkStateReader;
import org.apache.solr.common.cloud.ZooKeeperException;
import org.apache.solr.common.util.EnvUtils;
import org.apache.solr.common.util.ExecutorUtil;
import org.apache.solr.common.util.IOUtils;
import org.apache.solr.common.util.SolrNamedThreadFactory;
import org.apache.solr.common.util.StrUtils;
import org.apache.solr.logging.MDCLoggingContext;
import org.apache.solr.metrics.SolrMetricProducer;
import org.apache.solr.metrics.SolrMetricsContext;
import org.apache.solr.metrics.otel.OtelUnit;
import org.apache.zookeeper.KeeperException;
import org.apache.zookeeper.server.embedded.ZooKeeperServerEmbedded;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Used by {@link CoreContainer} to hold ZooKeeper / SolrCloud info, especially {@link
 * ZkController}. Mainly it does some ZK initialization, and ensures a loading core registers in ZK.
 * Even when in standalone mode, perhaps surprisingly, an instance of this class exists. If {@link
 * #getZkController()} returns null then we're in standalone mode.
 */
public class ZkContainer {
  // NOTE DWS: It's debatable if this in-between class is needed instead of folding it all into
  // ZkController. ZKC is huge though.

  private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

  // Port offsets for embedded ZooKeeper quorum configuration
  // When running in quorum mode, Solr's host port is used as a base, and these offsets
  // calculate the various ZK ports needed for cluster coordination
  private static final int ZK_CLIENT_PORT_OFFSET = 1000;
  private static final int ZK_QUORUM_PORT_OFFSET = -4000;
  private static final int ZK_LEADER_ELECTION_PORT_OFFSET = -3000;
  private static final int ZK_CLIENT_CONNECT_TIMEOUT_ENSEMBLE = 24 * 60 * 60 * 1000; // 1 day

  private static final String OPERATION_ATTR = "operation";

  protected ZkController zkController;

  // zkServer (and SolrZkServer) wrap a ZooKeeperServerMain if standalone mode, but in quorum we
  // just use ZooKeeperServerEmbedded
  // directly!  Why?  Can we use ZooKeeperServerEmbedded in one node directly instead?
  private SolrZkServer zkServer;
  private ZooKeeperServerEmbedded zkServerEmbedded;

  private ExecutorService coreZkRegister =
      ExecutorUtil.newMDCAwareCachedThreadPool(new SolrNamedThreadFactory("coreZkRegister"));

  private SolrMetricProducer metricProducer;

  private List<AutoCloseable> toClose;

  public ZkContainer() {}

  /**
   * Builder for ZooKeeper configuration file (zoo.cfg) content.
   *
   * <p>This class generates the configuration content needed for ZooKeeperServerEmbedded when
   * running in quorum mode. It handles server entries, data directories, and various ZK settings.
   */
  private static class ZooKeeperConfigBuilder {
    private Path dataDir;
    private int clientPort;
    private int tickTime = 2000;
    private int initLimit = 10;
    private int syncLimit = 5;
    private List<String> fourLetterWordCommands = List.of("mntr", "conf", "ruok");
    private boolean adminServerEnabled = false;
    private final List<QuorumServerEntry> servers = new ArrayList<>();

    /** Represents a single server entry in the ZooKeeper quorum configuration. */
    static class QuorumServerEntry {
      final int serverId;
      final String host;
      final int quorumPort;
      final int leaderElectionPort;

      QuorumServerEntry(int serverId, String host, int quorumPort, int leaderElectionPort) {
        this.serverId = serverId;
        this.host = host;
        this.quorumPort = quorumPort;
        this.leaderElectionPort = leaderElectionPort;
      }
    }

    ZooKeeperConfigBuilder setDataDir(Path dataDir) {
      this.dataDir = dataDir;
      return this;
    }

    ZooKeeperConfigBuilder setClientPort(int clientPort) {
      this.clientPort = clientPort;
      return this;
    }

    ZooKeeperConfigBuilder addServer(int id, String host, int quorumPort, int leaderPort) {
      servers.add(new QuorumServerEntry(id, host, quorumPort, leaderPort));
      return this;
    }

    /**
     * Builds the zoo.cfg configuration content.
     *
     * @return the complete zoo.cfg file content as a string
     */
    String buildConfig() {
      // Base configuration template
      String template =
          """
          tickTime=%d
          initLimit=%d
          syncLimit=%d
          dataDir=%s
          4lw.commands.whitelist=%s
          admin.enableServer=%s
          clientPort=%d
          """;

      StringBuilder config = new StringBuilder();
      config.append(
          String.format(
              template,
              tickTime,
              initLimit,
              syncLimit,
              dataDir.toString(),
              String.join(",", fourLetterWordCommands),
              adminServerEnabled,
              clientPort));

      // Append server entries
      for (QuorumServerEntry server : servers) {
        config.append(
            String.format(
                "server.%d=%s:%d:%d%n",
                server.serverId, server.host, server.quorumPort, server.leaderElectionPort));
      }

      return config.toString();
    }
  }

  /**
   * Initializes an embedded ZooKeeper quorum.
   *
   * <p>This class handles the complex setup required to run ZooKeeper in quorum mode within Solr
   * nodes. It generates the zoo.cfg configuration, determines the node's myId by matching against
   * the zkHost connection string, creates necessary directories, and starts the embedded ZK server.
   */
  private static class ZkQuorumInitializer {
    private final Path solrHome;
    private final CloudConfig cloudConfig;
    private final Path zkHomeDir;
    private final Path zkDataDir;

    ZkQuorumInitializer(Path solrHome, CloudConfig cloudConfig) {
      this.solrHome = solrHome;
      this.cloudConfig = cloudConfig;
      this.zkHomeDir = solrHome.resolve("zoo_home");
      this.zkDataDir = zkHomeDir.resolve("data");
    }

    /**
     * Initializes and starts the ZooKeeper quorum server.
     *
     * @return the started ZooKeeperServerEmbedded instance
     * @throws Exception if initialization fails
     */
    ZooKeeperServerEmbedded initializeQuorum() throws Exception {
      // Calculate the ZK client port based on Solr's host port
      final int zkPort = cloudConfig.getSolrHostPort() + ZK_CLIENT_PORT_OFFSET;

      // Build zoo.cfg configuration
      ZooKeeperConfigBuilder configBuilder =
          new ZooKeeperConfigBuilder().setDataDir(zkDataDir).setClientPort(zkPort);

      // Parse zkHost to add all servers and determine this node's myId
      final String[] zkHosts = cloudConfig.getZkHost().split(",");
      int myId = determineMyId(zkHosts, cloudConfig.getHost(), zkPort);

      // Add all quorum members to the configuration
      for (int i = 0; i < zkHosts.length; i++) {
        final String[] hostComponents = zkHosts[i].split(":");
        final String zkServer = hostComponents[0];
        final int zkClientPort = Integer.parseInt(hostComponents[1]);
        final int zkQuorumPort = zkClientPort + ZK_QUORUM_PORT_OFFSET;
        final int zkLeaderPort = zkClientPort + ZK_LEADER_ELECTION_PORT_OFFSET;

        configBuilder.addServer(i + 1, zkServer, zkQuorumPort, zkLeaderPort);
      }

      String zooCfgContents = configBuilder.buildConfig();

      // Create directories and write configuration files
      Files.createDirectories(zkHomeDir);
      Files.writeString(zkHomeDir.resolve("zoo.cfg"), zooCfgContents);
      Files.createDirectories(zkDataDir);
      Files.writeString(zkDataDir.resolve("myid"), String.valueOf(myId));

      // Start the embedded ZooKeeper server
      return startZooKeeperServerEmbedded(zkPort, zkHomeDir.toString());
    }

    /**
     * Determines this node's myId by matching hostname:port against the zkHost connection string.
     *
     * @param zkHosts array of host:port strings from zkHost
     * @param hostName this node's hostname
     * @param zkPort this node's ZK client port
     * @return the myId (1-based index) for this node
     * @throws IllegalStateException if unable to determine myId
     */
    private int determineMyId(String[] zkHosts, String hostName, int zkPort) {
      final String targetConnStringSection = hostName + ":" + zkPort;
      if (log.isInfoEnabled()) {
        log.info(
            "Trying to match {} against zkHostString {} to determine myid",
            targetConnStringSection,
            cloudConfig.getZkHost());
      }

      for (int i = 0; i < zkHosts.length; i++) {
        if (targetConnStringSection.equals(zkHosts[i])) {
          return i + 1; // myId is 1-based
        }
      }

      throw new IllegalStateException(
          "Unable to determine ZK 'myid' for target " + targetConnStringSection);
    }

    /**
     * Starts the ZooKeeperServerEmbedded instance.
     *
     * @param port the client port
     * @param zkHomeDir the ZK home directory path
     * @return the started server instance
     * @throws Exception if startup fails
     */
    private ZooKeeperServerEmbedded startZooKeeperServerEmbedded(int port, String zkHomeDir)
        throws Exception {
      Properties p = new Properties();
      try (FileReader fr = new FileReader(zkHomeDir + "/zoo.cfg", StandardCharsets.UTF_8)) {
        p.load(fr);
      }
      p.setProperty("clientPort", String.valueOf(port));

      ZooKeeperServerEmbedded server =
          ZooKeeperServerEmbedded.builder().baseDir(Path.of(zkHomeDir)).configuration(p).build();
      server.start();
      log.info("Started embedded ZooKeeper server in quorum mode on port {}", port);
      return server;
    }
  }

  /**
   * Metrics producer for ZooKeeper client operations.
   *
   * <p>Registers observable counters for various ZK operations including reads, writes, deletes,
   * watch events, and data transfer metrics.
   */
  private class ZkClientMetricsProducer implements SolrMetricProducer {
    private final ZkController zkController;
    private SolrMetricsContext metricsContext;

    ZkClientMetricsProducer(ZkController zkController) {
      this.zkController = zkController;
    }

    @Override
    public void initializeMetrics(SolrMetricsContext parentContext, Attributes attributes) {
      final List<AutoCloseable> observables = new ArrayList<>();
      metricsContext = parentContext.getChildContext(this);

      var metricsListener = zkController.getZkClient().getMetrics();

      registerOperationsMetrics(observables, metricsListener, attributes);
      registerBytesMetrics(observables, metricsListener, attributes);
      registerWatchMetrics(observables, metricsListener, attributes);
      registerChildFetchMetrics(observables, metricsListener, attributes);

      // Store observables in the outer class for cleanup
      toClose = Collections.unmodifiableList(observables);
    }

    private void registerOperationsMetrics(
        List<AutoCloseable> observables,
        org.apache.solr.common.cloud.SolrZKMetricsListener metricsListener,
        Attributes attributes) {
      observables.add(
          metricsContext.observableLongCounter(
              "solr_zk_ops",
              "Total number of ZooKeeper operations",
              measurement -> {
                measurement.record(
                    metricsListener.getReads(),
                    attributes.toBuilder().put(OPERATION_ATTR, "read").build());
                measurement.record(
                    metricsListener.getDeletes(),
                    attributes.toBuilder().put(OPERATION_ATTR, "delete").build());
                measurement.record(
                    metricsListener.getWrites(),
                    attributes.toBuilder().put(OPERATION_ATTR, "write").build());
                measurement.record(
                    metricsListener.getMultiOps(),
                    attributes.toBuilder().put(OPERATION_ATTR, "multi").build());
                measurement.record(
                    metricsListener.getExistsChecks(),
                    attributes.toBuilder().put(OPERATION_ATTR, "exists").build());
              }));
    }

    private void registerBytesMetrics(
        List<AutoCloseable> observables,
        org.apache.solr.common.cloud.SolrZKMetricsListener metricsListener,
        Attributes attributes) {
      observables.add(
          metricsContext.observableLongCounter(
              "solr_zk_read",
              "Total bytes read from ZooKeeper",
              measurement -> {
                measurement.record(metricsListener.getBytesRead(), attributes);
              },
              OtelUnit.BYTES));

      observables.add(
          metricsContext.observableLongCounter(
              "solr_zk_written",
              "Total bytes written to ZooKeeper",
              measurement -> {
                measurement.record(metricsListener.getBytesWritten(), attributes);
              },
              OtelUnit.BYTES));
    }

    private void registerWatchMetrics(
        List<AutoCloseable> observables,
        org.apache.solr.common.cloud.SolrZKMetricsListener metricsListener,
        Attributes attributes) {
      observables.add(
          metricsContext.observableLongCounter(
              "solr_zk_watches_fired",
              "Total number of ZooKeeper watches fired",
              measurement -> {
                measurement.record(metricsListener.getWatchesFired(), attributes);
              }));
    }

    private void registerChildFetchMetrics(
        List<AutoCloseable> observables,
        org.apache.solr.common.cloud.SolrZKMetricsListener metricsListener,
        Attributes attributes) {
      observables.add(
          metricsContext.observableLongCounter(
              "solr_zk_cumulative_multi_ops_total",
              "Total cumulative multi-operations count",
              measurement -> {
                measurement.record(metricsListener.getCumulativeMultiOps(), attributes);
              }));

      observables.add(
          metricsContext.observableLongCounter(
              "solr_zk_child_fetches",
              "Total number of ZooKeeper child node fetches",
              measurement -> {
                measurement.record(metricsListener.getChildFetches(), attributes);
              }));

      observables.add(
          metricsContext.observableLongCounter(
              "solr_zk_cumulative_children_fetched",
              "Total cumulative children fetched count",
              measurement -> {
                measurement.record(metricsListener.getCumulativeChildrenFetched(), attributes);
              }));
    }

    @Override
    public SolrMetricsContext getSolrMetricsContext() {
      return metricsContext;
    }
  }

  /**
   * Checks if this node should run as part of a ZooKeeper quorum.
   *
   * @param cc the CoreContainer
   * @return true if node is configured for quorum mode
   */
  private boolean isZkQuorumNode(CoreContainer cc) {
    return NodeRoles.MODE_ON.equals(cc.nodeRoles.getRoleMode(NodeRoles.Role.ZOOKEEPER_QUORUM));
  }

  /**
   * Initializes an embedded ZooKeeper quorum for this node.
   *
   * @param solrHome Solr home directory
   * @param config cloud configuration
   * @return the started ZooKeeperServerEmbedded instance
   */
  private ZooKeeperServerEmbedded initializeEmbeddedQuorum(Path solrHome, CloudConfig config) {
    try {
      ZkQuorumInitializer initializer = new ZkQuorumInitializer(solrHome, config);
      return initializer.initializeQuorum();
    } catch (Exception e) {
      throw new ZooKeeperException(
          SolrException.ErrorCode.SERVER_ERROR,
          "Failed to initialize embedded ZooKeeper quorum: " + e.getMessage(),
          e);
    }
  }

  /**
   * Calculates the appropriate ZK client connection timeout based on deployment mode.
   *
   * @param zkServerEnabled whether embedded ZK is enabled
   * @param runAsQuorum whether running in quorum mode
   * @param zkServer the SolrZkServer instance (may be null)
   * @return timeout in milliseconds
   */
  private int calculateZkClientConnectTimeout(
      boolean zkServerEnabled, boolean runAsQuorum, SolrZkServer zkServer) {
    // For ensembles and quorums, use extended timeout to allow other nodes to start
    if (zkServerEnabled && zkServer != null && zkServer.getServers().size() > 1) {
      log.info(
          "Waiting for a quorum (ensemble mode with {} servers).", zkServer.getServers().size());
      return ZK_CLIENT_CONNECT_TIMEOUT_ENSEMBLE;
    } else if (zkServerEnabled && runAsQuorum) {
      log.info("Waiting for a quorum (quorum mode).");
      return ZK_CLIENT_CONNECT_TIMEOUT_ENSEMBLE;
    }
    return SolrZkClientTimeout.DEFAULT_ZK_CONNECT_TIMEOUT;
  }

  /**
   * Initializes the ZkController and configures HTTPS if needed.
   *
   * @param cc the CoreContainer
   * @param config cloud configuration
   * @param zookeeperHost ZK connection string
   * @param zkClientConnectTimeout connection timeout
   * @param zkServerEnabled whether embedded ZK is enabled
   * @throws InterruptedException if interrupted during initialization
   * @throws TimeoutException if connection times out
   * @throws IOException on I/O errors
   * @throws KeeperException on ZK errors
   */
  private void initializeZkController(
      CoreContainer cc,
      CloudConfig config,
      String zookeeperHost,
      int zkClientConnectTimeout,
      boolean zkServerEnabled)
      throws InterruptedException, TimeoutException, IOException, KeeperException {

    log.info("Zookeeper client={}", zookeeperHost);

    boolean createRoot = EnvUtils.getPropertyAsBool("solr.zookeeper.chroot.create", false);

    if (!ZkController.checkChrootPath(zookeeperHost, createRoot)) {
      throw new ZooKeeperException(
          SolrException.ErrorCode.SERVER_ERROR,
          "A chroot was specified in ZkHost but the znode doesn't exist. " + zookeeperHost);
    }

    this.zkController = new ZkController(cc, zookeeperHost, zkClientConnectTimeout, config);

    // Configure HTTPS scheme for embedded ZK if SSL is enabled
    if (zkServerEnabled && StrUtils.isNotNullOrEmpty(System.getProperty(HTTPS_PORT_PROP))) {
      new ClusterProperties(zkController.getZkClient())
          .setClusterProperty(ZkStateReader.URL_SCHEME, HTTPS);
    }
  }

  public void initZooKeeper(final CoreContainer cc, CloudConfig config) {
    // zkServerEnabled is set whenever in solrCloud mode ('-c') but no explicit zkHost/ZK_HOST is
    // provided.
    final boolean zkServerEnabled =
        EnvUtils.getPropertyAsBool("solr.zookeeper.server.enabled", false);
    final boolean zkQuorumNode = isZkQuorumNode(cc);

    if (zkQuorumNode) {
      log.info("Starting node in ZooKeeper Quorum role.");
    }

    if (zkServerEnabled && config == null) {
      throw new SolrException(
          SolrException.ErrorCode.SERVER_ERROR,
          "Cannot start Solr in cloud mode - no cloud config provided");
    }

    if (config == null) {
      log.info("Solr is running in standalone mode");
      return;
    }

    final boolean runAsQuorum = config.getZkHost() != null && zkQuorumNode;
    String zookeeperHost = config.getZkHost();
    final Path solrHome = cc.getSolrHome();

    // Start embedded ZooKeeper if needed
    if (zkServerEnabled) {
      if (runAsQuorum) {
        zkServerEmbedded = initializeEmbeddedQuorum(solrHome, config);
      } else {
        zkServer =
            SolrZkServer.createAndStart(config.getZkHost(), solrHome, config.getSolrHostPort());
        if (zookeeperHost == null) {
          zookeeperHost = zkServer.getClientString();
        }
      }
    }

    // Initialize ZK client and controller if we have a ZK host
    if (zookeeperHost != null) {
      try {
        int zkClientConnectTimeout =
            calculateZkClientConnectTimeout(zkServerEnabled, runAsQuorum, zkServer);

        initializeZkController(cc, config, zookeeperHost, zkClientConnectTimeout, zkServerEnabled);

        // Initialize metrics producer
        // Observables will be stored in toClose when initializeMetrics is called
        this.metricProducer = new ZkClientMetricsProducer(zkController);

      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        log.error("Interrupted while initializing ZooKeeper controller", e);
        throw new ZooKeeperException(
            SolrException.ErrorCode.SERVER_ERROR,
            "Interrupted while initializing ZooKeeper controller",
            e);
      } catch (TimeoutException e) {
        log.error("Connection timeout while connecting to ZooKeeper: {}", zookeeperHost, e);
        throw new ZooKeeperException(
            SolrException.ErrorCode.SERVER_ERROR,
            "Connection timeout while connecting to ZooKeeper: " + zookeeperHost,
            e);
      } catch (IOException | KeeperException e) {
        log.error("Failed to initialize ZooKeeper controller", e);
        throw new ZooKeeperException(
            SolrException.ErrorCode.SERVER_ERROR,
            "Failed to initialize ZooKeeper controller: " + e.getMessage(),
            e);
      }
    }
  }

  public static volatile Predicate<CoreDescriptor> testing_beforeRegisterInZk;

  public void registerInZk(final SolrCore core, boolean background, boolean skipRecovery) {
    if (zkController == null) {
      return;
    }

    CoreDescriptor cd = core.getCoreDescriptor(); // save this here - the core may not have it later
    Runnable r =
        () -> {
          MDCLoggingContext.setCore(core);
          try {
            try {
              if (testing_beforeRegisterInZk != null) {
                boolean didTrigger = testing_beforeRegisterInZk.test(cd);
                if (log.isDebugEnabled()) {
                  log.debug("{} pre-zk hook", (didTrigger ? "Ran" : "Skipped"));
                }
              }
              if (!core.getCoreContainer().isShutDown()) {
                zkController.register(core.getName(), cd, skipRecovery);
              }
            } catch (InterruptedException e) {
              // Restore the interrupted status
              Thread.currentThread().interrupt();
              log.error("Interrupted", e);
            } catch (KeeperException e) {
              log.error("KeeperException registering core {}", core.getName(), e);
            } catch (IllegalStateException ignore) {

            } catch (Exception e) {
              log.error("Exception registering core {}", core.getName(), e);
              try {
                zkController.publish(cd, Replica.State.DOWN);
              } catch (InterruptedException e1) {
                Thread.currentThread().interrupt();
                log.error("Interrupted", e1);
              } catch (Exception e1) {
                log.error("Exception publishing down state for core {}", core.getName(), e1);
              }
            }
          } finally {
            MDCLoggingContext.clear();
          }
        };

    if (background) {
      coreZkRegister.execute(r);
    } else {
      r.run();
    }
  }

  public ZkController getZkController() {
    return zkController;
  }

  public void close() {

    try {
      ExecutorUtil.shutdownAndAwaitTermination(coreZkRegister);
    } finally {
      try {
        if (zkController != null) {
          zkController.close();
        }
      } finally {
        try {
          if (zkServer != null) {
            zkServer.stop();
          }
        } finally {
          if (zkServerEmbedded != null) {
            try {
              zkServerEmbedded.close();
              log.info("Closed embedded ZooKeeper server in quorum mode");
            } catch (Exception e) {
              log.error("Error closing embedded ZooKeeper server", e);
            }
          }
        }
      }
      IOUtils.closeQuietly(toClose);
    }
  }

  public ExecutorService getCoreZkRegisterExecutorService() {
    return coreZkRegister;
  }

  public SolrMetricProducer getZkMetricsProducer() {
    return this.metricProducer;
  }
}
