package org.cdpg.dx.auth.authentication.handler;

import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import io.vertx.ext.auth.User;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.impl.AuthenticationHandlerInternal;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.cdpg.dx.auth.appid.handler.AppIdAuthHandler;
import org.cdpg.dx.common.config.HttpConstants;

/**
 * Single auth handler that dispatches based on the Authorization header scheme:
 *   Authorization: Basic ...  → AppId gRPC flow  ({@link AppIdAuthHandler})
 *   Authorization: Bearer ... → JWT flow          ({@link MultiIssuerJwtAuthHandler})
 *
 * <p>Registered as the {@code "authorization"} OpenAPI security scheme so no ChainAuthHandler
 * is needed (avoids classloader issues in exec:java mode).
 *
 * <p>Lives in dx-common so any DX service can wire up combined Basic+Bearer auth by
 * instantiating this handler in their verticle.
 */
public class CombinedAuthHandler implements AuthenticationHandlerInternal {

  private static final Logger LOGGER = LogManager.getLogger(CombinedAuthHandler.class);

  private final AppIdAuthHandler appIdHandler;
  private final MultiIssuerJwtAuthHandler jwtHandler;

  public CombinedAuthHandler(AppIdAuthHandler appIdHandler, MultiIssuerJwtAuthHandler jwtHandler) {
    this.appIdHandler = appIdHandler;
    this.jwtHandler = jwtHandler;
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
    String authHeader = ctx.request().getHeader(HttpConstants.HEADER_AUTHORIZATION);
    LOGGER.debug("CombinedAuthHandler: authHeader={}", authHeader);
    if (authHeader != null && authHeader.startsWith(HttpConstants.BASIC_PREFIX)) {
      appIdHandler.authenticate(ctx, handler);
    } else {
      jwtHandler.authenticate(ctx, handler);
    }
  }

  @Override
  public void postAuthentication(RoutingContext ctx) {
    String principalAppId = ctx.user().principal().getString(AppIdAuthHandler.PRINCIPAL_APP_ID_KEY);
    if (principalAppId != null) {
      appIdHandler.postAuthentication(ctx);
    } else {
      ctx.next();
    }
  }
}
