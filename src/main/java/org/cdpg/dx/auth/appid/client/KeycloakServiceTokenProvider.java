package org.cdpg.dx.auth.appid.client;

import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.client.WebClient;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Fetches and caches a Keycloak service identity token via OAuth2 {@code client_credentials}
 * grant. The token identifies this service (e.g. {@code azp = svc-dx-dataplane}) and must be
 * passed on every outbound gRPC call to dx-controlplane.
 *
 * <p>Generic — any service that calls dx-controlplane gRPC instantiates this with its own
 * {@code clientId} and {@code clientSecret}. Each service follows the same Keycloak setup steps.
 *
 * <p>The cached token is refreshed {@value #REFRESH_BUFFER_SECONDS} seconds before expiry so
 * gRPC calls never use a token that is about to expire.
 */
public class KeycloakServiceTokenProvider {

  private static final Logger LOGGER = LogManager.getLogger(KeycloakServiceTokenProvider.class);
  private static final int REFRESH_BUFFER_SECONDS = 60;

  private final WebClient webClient;
  private final String tokenUrl;
  private final String clientId;
  private final String clientSecret;

  private volatile String cachedToken;
  private volatile Instant tokenExpiresAt = Instant.EPOCH;

  public KeycloakServiceTokenProvider(
      Vertx vertx, String tokenUrl, String clientId, String clientSecret) {
    this.webClient = WebClient.create(vertx);
    this.tokenUrl = tokenUrl;
    this.clientId = clientId;
    this.clientSecret = clientSecret;
  }

  /**
   * Returns a valid service token. Returns the cached token if still fresh; otherwise fetches a
   * new one from Keycloak.
   */
  public Future<String> getServiceToken() {
    String token = cachedToken;
    if (token != null
        && Instant.now().isBefore(tokenExpiresAt.minusSeconds(REFRESH_BUFFER_SECONDS))) {
      return Future.succeededFuture(token);
    }
    return fetchToken();
  }

  private Future<String> fetchToken() {
    Promise<String> promise = Promise.promise();

    String body =
        "grant_type=client_credentials"
            + "&client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8)
            + "&client_secret=" + URLEncoder.encode(clientSecret, StandardCharsets.UTF_8);

    webClient
        .postAbs(tokenUrl)
        .putHeader("Content-Type", "application/x-www-form-urlencoded")
        .sendBuffer(Buffer.buffer(body))
        .onSuccess(
            response -> {
              if (response.statusCode() != 200) {
                LOGGER.error(
                    "Keycloak token fetch failed: status={} body={}",
                    response.statusCode(),
                    response.bodyAsString());
                promise.fail("Keycloak returned HTTP " + response.statusCode());
                return;
              }
              JsonObject json = response.bodyAsJsonObject();
              String accessToken = json.getString("access_token");
              if (accessToken == null) {
                promise.fail("No access_token in Keycloak response");
                return;
              }
              int expiresIn = json.getInteger("expires_in", 300);
              cachedToken = accessToken;
              tokenExpiresAt = Instant.now().plusSeconds(expiresIn);
              LOGGER.info(
                  "Fetched new service token for clientId={}, expires in {}s",
                  clientId,
                  expiresIn);
              promise.complete(accessToken);
            })
        .onFailure(
            err -> {
              LOGGER.error(
                  "Failed to fetch service token from Keycloak tokenUrl={}: {}",
                  tokenUrl,
                  err.getMessage());
              promise.fail(err);
            });

    return promise.future();
  }
}
