package org.cdpg.dx.auth.appid.cache;

import io.vertx.core.Future;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonObject;
import io.vertx.rabbitmq.QueueOptions;
import io.vertx.rabbitmq.RabbitMQClient;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.cdpg.dx.auth.appid.handler.AppIdAuthHandler;

/**
 * Consumes AppId revocation messages from RabbitMQ and directly invalidates
 * the in-process caches.
 *
 * <p>On {@link #start()}, declares the queue and binds it to the exchange (routing key {@code #})
 * so no manual RabbitMQ setup is required. On each message, calls {@code invalidate(appId)} on
 * both caches.
 *
 * <p>Expected message format: {@code { "appId": "<the-revoked-app-id>" }}
 */
public class AppIdRevocationConsumer {

  private static final Logger LOGGER = LogManager.getLogger(AppIdRevocationConsumer.class);

  private static final QueueOptions QUEUE_OPTIONS =
      new QueueOptions().setMaxInternalQueueSize(1000).setKeepMostRecent(true);

  private final RabbitMQClient rabbitMQClient;
  private final AppIdCacheService appIdCacheService;
  private final AppIdItemAccessCacheService itemAccessCacheService;
  private final String exchangeName;
  private final String queueName;

  public AppIdRevocationConsumer(
      RabbitMQClient rabbitMQClient,
      AppIdCacheService appIdCacheService,
      AppIdItemAccessCacheService itemAccessCacheService,
      String exchangeName,
      String queueName) {
    this.rabbitMQClient = rabbitMQClient;
    this.appIdCacheService = appIdCacheService;
    this.itemAccessCacheService = itemAccessCacheService;
    this.exchangeName = exchangeName;
    this.queueName = queueName;
  }

  public Future<Void> start() {
    // RabbitClient fires client.start() asynchronously in its constructor — the connection may
    // not be established yet when onBrokerReady() is called. Connect first if needed.
    Future<Void> connectionFuture =
        rabbitMQClient.isConnected() ? Future.succeededFuture() : rabbitMQClient.start();

    return connectionFuture
        // Declare durable, non-exclusive, non-auto-delete queue — idempotent if already exists
        .compose(v -> rabbitMQClient.queueDeclare(queueName, true, false, false))
        // Bind queue to exchange with wildcard routing key so all revocation events are received
        .compose(declareOk -> rabbitMQClient.queueBind(queueName, exchangeName, "##"))
        .compose(v -> rabbitMQClient.basicConsumer(queueName, QUEUE_OPTIONS))
        .onSuccess(consumer -> {
          LOGGER.info("AppIdRevocationConsumer started exchange={} queue={}", exchangeName, queueName);
          consumer.handler(message -> {
            Buffer body = message.body();
            if (body == null || body.length() == 0) {
              LOGGER.warn("Empty message received on revocation queue={}", queueName);
              return;
            }
            try {
              JsonObject payload = new JsonObject(body);
              String appId = payload.getString(AppIdAuthHandler.APP_ID_KEY);
              if (appId == null || appId.isBlank()) {
                LOGGER.warn("Missing or blank appId in revocation message: {}", payload);
                return;
              }
              LOGGER.info("Revoking cache for appId={}", appId);
              appIdCacheService.invalidate(appId);
              itemAccessCacheService.invalidate(appId);
              AppIdCacheHolder.invalidateCredentials(appId);
            } catch (Exception e) {
              LOGGER.error("Failed to process revocation message: {}", e.getMessage());
            }
          });
        })
        .onFailure(err -> LOGGER.error("Failed to start AppIdRevocationConsumer: {}", err.getMessage()))
        .mapEmpty();
  }
}
