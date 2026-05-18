package org.cdpg.dx.auth.authentication.client;

import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.JWTOptions;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTAuthOptions;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.cdpg.dx.auth.common.AuthConstants;
import org.cdpg.dx.keycloak.config.KeycloakConstants;

public class JwksResolver {

  private static final Logger LOGGER = LogManager.getLogger(JwksResolver.class);

  private static final int  DEFAULT_LEEWAY     = 60;
  private static final long DEFAULT_REFRESH_MS = 600_000L;

  private final Map<String, JWTAuth> cache = new ConcurrentHashMap<>();
  private final JsonObject issuerConfig;
  private final JwksClient jwksClient;
  private final boolean ignoreExpiry;
  private final int leeway;
  private final Vertx vertx;

  public JwksResolver(
      Vertx vertx, JsonObject issuerConfig, Supplier<Future<JsonObject>> internalJwksProvider) {
    this.issuerConfig = issuerConfig;
    this.vertx = vertx;
    this.ignoreExpiry = issuerConfig.getBoolean(AuthConstants.JWT_IGNORE_EXPIRY, false);
    this.leeway = issuerConfig.getInteger(AuthConstants.JWT_LEEWAY, DEFAULT_LEEWAY);
    this.jwksClient = new JwksClient(vertx, internalJwksProvider);

    long resetIntervalMs = issuerConfig.getLong(AuthConstants.JWKS_REFRESH_INTERVAL, DEFAULT_REFRESH_MS);
    vertx.setPeriodic(resetIntervalMs, id -> {
      LOGGER.info("Resetting JWKS cache after {} ms", resetIntervalMs);
      cache.clear();
    });
  }

  public Future<JWTAuth> resolve(String issuer, String kid) {
    String cacheKey = issuer + "#" + kid;
    LOGGER.debug("Resolving JWTAuth for issuer: {}, kid: {}", issuer, kid);

    if (cache.containsKey(cacheKey)) {
      LOGGER.info("cache hit for issuer {}, kid {}", issuer, kid);
      return Future.succeededFuture(cache.get(cacheKey));
    }
    LOGGER.info("cache miss - need to create JWTAuth provider for issuer {}, kid {}", issuer, kid);

    JsonObject cfg = issuerConfig.getJsonObject(issuer);
    if (cfg == null) {
      return Future.failedFuture("Unknown issuer: " + issuer);
    }
    String type    = cfg.getString(AuthConstants.JWKS_TYPE, JwksClient.TYPE_REMOTE);
    String jwksUrl = cfg.getString(AuthConstants.JWKS_URL);

    return jwksClient
        .fetchJwks(type, jwksUrl)
        .compose(jwks -> {
          List<JsonObject> keys =
              jwks.getJsonArray(KeycloakConstants.JWKS_KEYS).stream()
                  .map(obj -> (JsonObject) obj)
                  .filter(k -> kid.equals(k.getString(KeycloakConstants.CLAIM_KID)))
                  .collect(Collectors.toList());

          if (keys.isEmpty()) {
            return Future.failedFuture("No JWK found for issuer: " + issuer + ", kid: " + kid);
          }

          JWTAuthOptions options =
              new JWTAuthOptions()
                  .setJwks(keys)
                  .setJWTOptions(
                      new JWTOptions()
                          .setLeeway(leeway)
                          .setIgnoreExpiration(ignoreExpiry)
                          .setIssuer(issuer));

          JWTAuth jwtAuth = JWTAuth.create(vertx, options);
          cache.put(cacheKey, jwtAuth);
          LOGGER.info("Created new JWTAuth provider for issuer {}, kid {}", issuer, kid);
          return Future.succeededFuture(jwtAuth);
        });
  }
}
