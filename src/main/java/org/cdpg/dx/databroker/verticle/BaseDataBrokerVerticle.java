package org.cdpg.dx.databroker.verticle;

import static org.cdpg.dx.common.config.ServiceProxyAddressConstants.DATA_BROKER_SERVICE_ADDRESS;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.eventbus.MessageConsumer;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.client.WebClient;
import io.vertx.ext.web.client.WebClientOptions;
import io.vertx.rabbitmq.RabbitMQClient;
import io.vertx.rabbitmq.RabbitMQOptions;
import io.vertx.serviceproxy.ServiceBinder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.cdpg.dx.databroker.RabbitClient;
import org.cdpg.dx.databroker.RabbitWebClient;
import org.cdpg.dx.databroker.service.DataBrokerService;
import org.cdpg.dx.databroker.service.DataBrokerServiceImpl;
import org.cdpg.dx.databroker.util.Vhosts;

/**
 * Base verticle for setting up RabbitMQ infrastructure (clients, service proxy).
 *
 * <p>Subclasses should override {@link #onBrokerReady(RabbitMQClient, RabbitMQClient, RabbitClient)}
 * to set up project-specific message consumers (audit, email, leaderboard, etc.).
 *
 * <h3>Usage:</h3>
 * <pre>{@code
 * public class MyDataBrokerVerticle extends BaseDataBrokerVerticle {
 *   @Override
 *   protected void onBrokerReady(
 *       RabbitMQClient internalClient,
 *       RabbitMQClient prodClient,
 *       RabbitClient rabbitClient) {
 *     // Set up listeners
 *     new MyConsumer(internalClient).start();
 *   }
 * }
 * }</pre>
 */
public abstract class BaseDataBrokerVerticle extends AbstractVerticle {

  private static final Logger LOGGER = LogManager.getLogger(BaseDataBrokerVerticle.class);

  private ServiceBinder binder;
  private MessageConsumer<JsonObject> consumer;

  @Override
  public void start() throws Exception {
    // Read config
    String dataBrokerIp = config().getString("dataBrokerIP");
    int dataBrokerPort = config().getInteger("dataBrokerPort");
    int dataBrokerManagementPort = config().getInteger("dataBrokerManagementPort");
    String dataBrokerUserName = config().getString("dataBrokerUserName");
    String dataBrokerPassword = config().getString("dataBrokerPassword");
    int connectionTimeout = config().getInteger("connectionTimeout");
    int requestedHeartbeat = config().getInteger("requestedHeartbeat");
    int handshakeTimeout = config().getInteger("handshakeTimeout");
    int requestedChannelMax = config().getInteger("requestedChannelMax");
    int networkRecoveryInterval = config().getInteger("networkRecoveryInterval");
    String amqpUrl = config().getString("brokerAmqpIp");
    int amqpPort = config().getInteger("brokerAmqpPort");
    String isSSL = config().getString("portSsl", "false");

    // Configure RabbitMQ options
    RabbitMQOptions rabbitMQOptions = new RabbitMQOptions();
    rabbitMQOptions.setUser(dataBrokerUserName);
    rabbitMQOptions.setPassword(dataBrokerPassword);
    rabbitMQOptions.setHost(dataBrokerIp);
    rabbitMQOptions.setPort(dataBrokerPort);
    rabbitMQOptions.setConnectionTimeout(connectionTimeout);
    rabbitMQOptions.setRequestedHeartbeat(requestedHeartbeat);
    rabbitMQOptions.setHandshakeTimeout(handshakeTimeout);
    rabbitMQOptions.setRequestedChannelMax(requestedChannelMax);
    rabbitMQOptions.setNetworkRecoveryInterval(networkRecoveryInterval);
    rabbitMQOptions.setAutomaticRecoveryEnabled(true);

    String externalVhost = config().getString(Vhosts.IUDX_EXTERNAL.value);
    String prodVhost = config().getString(Vhosts.IUDX_PROD.value);
    String iudxInternalVhost = config().getString(Vhosts.IUDX_INTERNAL.value);

    RabbitMQOptions iudxConfig = new RabbitMQOptions(rabbitMQOptions);
    iudxConfig.setVirtualHost(prodVhost);

    RabbitMQOptions iudxInternalConfig = new RabbitMQOptions(rabbitMQOptions);
    iudxInternalConfig.setVirtualHost(iudxInternalVhost);

    WebClientOptions webConfig = new WebClientOptions();
    webConfig.setKeepAlive(true);
    webConfig.setConnectTimeout(86400000);
    webConfig.setDefaultHost(dataBrokerIp);
    webConfig.setDefaultPort(dataBrokerManagementPort);
    webConfig.setKeepAliveTimeout(86400000);
    if (isSSL.equals("true")) {
      webConfig.setSsl(true);
    } else {
      webConfig.setSsl(false);
    }

    // Create clients
    RabbitMQClient.create(vertx, rabbitMQOptions);
    WebClient.create(vertx, webConfig);

    JsonObject propObj = new JsonObject();
    propObj.put("username", dataBrokerUserName);
    propObj.put("password", dataBrokerPassword);

    RabbitWebClient rabbitWebClient = new RabbitWebClient(vertx, webConfig, propObj);
    RabbitMQClient iudxRabbitMqClient = RabbitMQClient.create(vertx, iudxConfig);
    RabbitMQClient iudxInternalRabbitMqClient = RabbitMQClient.create(vertx, iudxInternalConfig);
    RabbitClient rabbitClient =
        new RabbitClient(vertx, rabbitWebClient, iudxInternalRabbitMqClient, iudxRabbitMqClient);

    // Allow subclasses to set up consumers/listeners
    onBrokerReady(iudxInternalRabbitMqClient, iudxRabbitMqClient, rabbitClient);

    // Create and register DataBrokerService
    DataBrokerService dataBrokerService =
        new DataBrokerServiceImpl(
            rabbitClient, amqpUrl, amqpPort, iudxInternalVhost, prodVhost, externalVhost);

    binder = new ServiceBinder(vertx);
    consumer =
        binder
            .setAddress(DATA_BROKER_SERVICE_ADDRESS)
            .register(DataBrokerService.class, dataBrokerService);
  }

  /**
   * Called after RabbitMQ clients are initialized. Subclasses should override
   * this to set up message consumers, listeners, etc.
   *
   * @param internalClient the RabbitMQ client for the internal vhost
   * @param prodClient the RabbitMQ client for the production vhost
   * @param rabbitClient the higher-level RabbitClient wrapper
   */
  protected void onBrokerReady(
      RabbitMQClient internalClient, RabbitMQClient prodClient, RabbitClient rabbitClient) {
    // Default: no-op. Subclasses override.
  }

  @Override
  public void stop() throws Exception {
    if (binder != null && consumer != null) {
      binder.unregister(consumer);
    }
  }
}
