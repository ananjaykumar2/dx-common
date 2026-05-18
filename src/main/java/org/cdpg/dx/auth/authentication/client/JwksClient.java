package org.cdpg.dx.auth.authentication.client;

import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.client.WebClient;
import io.vertx.ext.web.client.WebClientOptions;
import java.util.function.Supplier;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.cdpg.dx.keycloak.config.KeycloakConstants;

public class JwksClient {

  private static final Logger LOGGER = LogManager.getLogger(JwksClient.class);

  public static final String TYPE_INTERNAL = "internal";
  public static final String TYPE_REMOTE   = "remote";

  private final WebClient client;
  private final Supplier<Future<JsonObject>> internalJwksProvider;

  public JwksClient(Vertx vertx, Supplier<Future<JsonObject>> internalJwksProvider) {
    this.client = WebClient.create(vertx, new WebClientOptions().setTrustAll(true));
    this.internalJwksProvider = internalJwksProvider;
  }

  public Future<JsonObject> fetchJwks(String type, String url) {
    if (TYPE_INTERNAL.equalsIgnoreCase(type)) {
      if (internalJwksProvider == null) {
        return Future.failedFuture("Internal JWKS provider not configured");
      }
      return internalJwksProvider.get();
    }

    if (TYPE_REMOTE.equals(type)) {
      return client
          .requestAbs(HttpMethod.GET, url)
          .send()
          .compose(resp -> {
            if (resp.statusCode() == 200 && resp.bodyAsJsonObject().containsKey(KeycloakConstants.JWKS_KEYS)) {
              return Future.succeededFuture(resp.bodyAsJsonObject());
            } else {
              return Future.failedFuture("Invalid JWKS response: " + resp.statusCode());
            }
          })
          .recover(err -> {
            LOGGER.error("Failed to fetch JWKs from {}: {}", url, err.getMessage());
            return Future.failedFuture(err);
          });
    }

    return Future.failedFuture("Unknown issuer type: " + type);
  }
}
