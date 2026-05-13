package org.cdpg.dx.auth.appid.handler;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.impl.AuthenticationHandlerInternal;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.cdpg.dx.auth.appid.cache.AppIdCacheService;
import org.cdpg.dx.auth.appid.client.AppIdVerificationClient;
import org.cdpg.dx.auth.appid.model.AppIdPrincipal;
import org.cdpg.dx.common.exception.DxUnauthorizedException;

/**
 * OpenAPI security handler for AppId/AppSecret authentication (Step 1 — identity only).
 *
 * <p>Verifies credentials via gRPC VerifyAppId, sets a minimal {@code ctx.user()} with
 * {@code sub}, {@code iss}, {@code realm_access.roles} so downstream
 * {@link org.cdpg.dx.auth.authorization.handler.AuthorizationHandler} passes, and stores the
 * {@code appId} string in routing-context data under {@link #APP_ID_KEY} so that a subsequent
 * per-entity access handler can perform the per-resource check.
 *
 * <p>Lives in dx-common so any DX service (dataplane, controlplane, etc.) can reuse it without
 * duplicating the Basic-auth decode + gRPC verification logic.
 */
public class AppIdAuthHandler implements AuthenticationHandlerInternal {

  /** Routing-context key that signals an AppId-authenticated request. */
  public static final String APP_ID_KEY = "appId";

  /** Temporary principal key used to pass appId from authenticate() to postAuthentication(). */
  public static final String PRINCIPAL_APP_ID_KEY = "_appId";

  private static final Logger LOGGER = LogManager.getLogger(AppIdAuthHandler.class);

  private final AppIdCacheService cacheService;
  private final AppIdVerificationClient verificationClient;

  public AppIdAuthHandler(AppIdCacheService cacheService, AppIdVerificationClient verificationClient) {
    this.cacheService = cacheService;
    this.verificationClient = verificationClient;
  }

  @Override
  public void handle(RoutingContext ctx) {
    authenticate(ctx, res -> {
      if (res.succeeded()) {
        ctx.setUser(res.result());
        postAuthentication(ctx);
      } else {
        ctx.fail(res.cause());
      }
    });
  }

  @Override
  public void authenticate(RoutingContext ctx, Handler<AsyncResult<User>> handler) {
    String authHeader = ctx.request().getHeader("Authorization");
    if (authHeader == null || !authHeader.startsWith("Basic ")) {
      handler.handle(Future.failedFuture(new DxUnauthorizedException("Missing or invalid Authorization header (expected Basic auth)")));
      return;
    }

    String appId;
    String appSecret;
    try {
      String decoded = new String(Base64.getDecoder().decode(authHeader.substring(6).trim()), StandardCharsets.UTF_8);
      int colonIdx = decoded.indexOf(':');
      if (colonIdx < 0) {
        handler.handle(Future.failedFuture(new DxUnauthorizedException("Invalid Basic auth format (expected base64(appId:appSecret))")));
        return;
      }
      appId = decoded.substring(0, colonIdx);
      appSecret = decoded.substring(colonIdx + 1);
    } catch (IllegalArgumentException e) {
      handler.handle(Future.failedFuture(new DxUnauthorizedException("Invalid Base64 in Authorization header")));
      return;
    }

    if (appId.isBlank() || appSecret.isBlank()) {
      handler.handle(Future.failedFuture(new DxUnauthorizedException("AppId or AppSecret must not be blank")));
      return;
    }

    cacheService
        .get(appId)
        .ifPresentOrElse(
            principal -> {
              LOGGER.debug("AppId cache hit for appId={}", appId);
              handler.handle(Future.succeededFuture(buildUser(principal)));
            },
            () -> verifyWithControlplane(appId, appSecret, handler));
  }

  @Override
  public void postAuthentication(RoutingContext ctx) {
    String appId = ctx.user().principal().getString(PRINCIPAL_APP_ID_KEY);
    if (appId != null) {
      ctx.put(APP_ID_KEY, appId);
      ctx.user().principal().remove(PRINCIPAL_APP_ID_KEY);
    }
    ctx.next();
  }

  private void verifyWithControlplane(String appId, String appSecret, Handler<AsyncResult<User>> handler) {
    verificationClient
        .verify(appId, appSecret)
        .onSuccess(response -> {
          if (!response.getSuccess()) {
            LOGGER.warn("AppId verification failed for appId={}", appId);
            handler.handle(Future.failedFuture(new DxUnauthorizedException("Invalid AppId credentials")));
            return;
          }
          AppIdPrincipal principal = AppIdPrincipal.fromProto(response.getPrincipal());
          LOGGER.debug("VerifyAppId gRPC response — appId={} userId={} roles={} scopes={} expiresAtEpoch={}",
              principal.appId(), principal.userId(), principal.roles(), principal.scopes(), principal.expiresAtEpoch());
          cacheService.put(appId, principal);
          handler.handle(Future.succeededFuture(buildUser(principal)));
        })
        .onFailure(err -> {
          LOGGER.error("gRPC verification error for appId={}: {}", appId, err.getMessage());
          handler.handle(Future.failedFuture(new DxUnauthorizedException("Authentication service unavailable")));
        });
  }

  private User buildUser(AppIdPrincipal principal) {
    List<String> roles = principal.roles().isEmpty() ? List.of("consumer") : principal.roles();
    JsonObject userPrincipal =
        new JsonObject()
            .put("sub", principal.userId())
            .put("iss", "dx-controlplane")
            .put("realm_access", new JsonObject().put("roles", new JsonArray(roles)))
            .put("scopes", new JsonArray(principal.scopes()))
            .put("organisation_id", principal.organisationId())
            .put(PRINCIPAL_APP_ID_KEY, principal.appId());
    return User.create(userPrincipal);
  }
}
