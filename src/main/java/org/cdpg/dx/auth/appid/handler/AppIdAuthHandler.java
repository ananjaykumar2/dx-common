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
import org.cdpg.dx.auth.appid.client.KeycloakServiceTokenProvider;
import org.cdpg.dx.auth.appid.model.AppIdPrincipal;
import org.cdpg.dx.auth.common.AuthConstants;
import org.cdpg.dx.auth.model.DxRole;
import org.cdpg.dx.common.config.HttpConstants;
import org.cdpg.dx.common.exception.DxUnauthorizedException;
import org.cdpg.dx.keycloak.config.KeycloakConstants;

/** OpenAPI security handler for AppId/AppSecret authentication (Step 1 — identity only). */
public class AppIdAuthHandler implements AuthenticationHandlerInternal {

  /** Routing-context key that signals an AppId-authenticated request. */
  public static final String APP_ID_KEY = "appId";

  /** Temporary principal key used to pass appId from authenticate() to postAuthentication(). */
  public static final String PRINCIPAL_APP_ID_KEY = "_appId";

  private static final Logger LOGGER = LogManager.getLogger(AppIdAuthHandler.class);

  private final AppIdCacheService cacheService;
  private final AppIdVerificationClient verificationClient;
  private final KeycloakServiceTokenProvider tokenProvider;

  public AppIdAuthHandler(
      AppIdCacheService cacheService,
      AppIdVerificationClient verificationClient,
      KeycloakServiceTokenProvider tokenProvider) {
    this.cacheService = cacheService;
    this.verificationClient = verificationClient;
    this.tokenProvider = tokenProvider;
  }

  @Override
  public void handle(RoutingContext ctx) {
    authenticate(
        ctx,
        res -> {
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
    String authHeader = ctx.request().getHeader(HttpConstants.HEADER_AUTHORIZATION);
    if (authHeader == null || !authHeader.startsWith(HttpConstants.BASIC_PREFIX)) {
      handler.handle(
          Future.failedFuture(new DxUnauthorizedException(AuthConstants.MISSING_BASIC_AUTH)));
      return;
    }

    String appId;
    String appSecret;
    try {
      String decoded =
          new String(
              Base64.getDecoder()
                  .decode(authHeader.substring(HttpConstants.BASIC_PREFIX.length()).trim()),
              StandardCharsets.UTF_8);
      int colonIdx = decoded.indexOf(':');
      if (colonIdx < 0) {
        handler.handle(
            Future.failedFuture(new DxUnauthorizedException(AuthConstants.INVALID_BASIC_FORMAT)));
        return;
      }
      appId = decoded.substring(0, colonIdx);
      appSecret = decoded.substring(colonIdx + 1);
    } catch (IllegalArgumentException e) {
      handler.handle(
          Future.failedFuture(new DxUnauthorizedException(AuthConstants.INVALID_BASE64)));
      return;
    }

    if (appId.isBlank() || appSecret.isBlank()) {
      handler.handle(
          Future.failedFuture(new DxUnauthorizedException(AuthConstants.BLANK_APP_CREDENTIALS)));
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

  private void verifyWithControlplane(
      String appId, String appSecret, Handler<AsyncResult<User>> handler) {
    tokenProvider
        .getServiceToken()
        .compose(token -> verificationClient.verify(appId, appSecret, token))
        .onSuccess(
            response -> {
              if (!response.getSuccess()) {
                LOGGER.warn("AppId verification failed for appId={}", appId);
                handler.handle(
                    Future.failedFuture(
                        new DxUnauthorizedException(AuthConstants.INVALID_APP_CREDENTIALS)));
                return;
              }
              AppIdPrincipal principal = AppIdPrincipal.fromProto(response.getPrincipal());
              LOGGER.debug(
                  "VerifyAppId gRPC response — appId={} userId={} roles={} scopes={} expiresAtEpoch={}",
                  principal.appId(),
                  principal.userId(),
                  principal.roles(),
                  principal.scopes(),
                  principal.expiresAtEpoch());
              cacheService.put(appId, principal);
              handler.handle(Future.succeededFuture(buildUser(principal)));
            })
        .onFailure(
            err -> {
              String msg = err.getMessage();
              if (msg != null && msg.startsWith("Service misconfiguration")) {
                LOGGER.error(
                    "Cannot verify appId={}: {} — fix config and restart", appId, msg);
              } else {
                LOGGER.error("gRPC VerifyAppId failed for appId={}: {}", appId, msg);
              }
              handler.handle(
                  Future.failedFuture(
                      new DxUnauthorizedException(AuthConstants.AUTH_SERVICE_UNAVAILABLE)));
            });
  }

  private User buildUser(AppIdPrincipal principal) {
    List<String> roles =
        principal.roles().isEmpty() ? List.of(DxRole.CONSUMER.value()) : principal.roles();
    JsonObject userPrincipal =
        new JsonObject()
            .put(KeycloakConstants.CLAIM_SUB, principal.userId())
            .put(KeycloakConstants.CLAIM_ISS, AuthConstants.ISSUER_DEFAULT)
            .put(
                KeycloakConstants.CLAIM_REALM_ACCESS,
                new JsonObject().put(KeycloakConstants.CLAIM_ROLES, new JsonArray(roles)))
            .put(KeycloakConstants.CLAIM_SCOPES, new JsonArray(principal.scopes()))
            .put(KeycloakConstants.ORGANISATION_ID, principal.organisationId())
            .put(PRINCIPAL_APP_ID_KEY, principal.appId());
    return User.create(userPrincipal);
  }
}
