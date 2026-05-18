package org.cdpg.dx.auth.authentication.handler;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authentication.TokenCredentials;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.impl.AuthenticationHandlerInternal;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.cdpg.dx.auth.authentication.client.JwksResolver;
import org.cdpg.dx.auth.authentication.util.BearerTokenExtractor;
import org.cdpg.dx.auth.authentication.util.JwtTokenUtil;
import org.cdpg.dx.auth.common.AuthConstants;
import org.cdpg.dx.common.exception.DxUnauthorizedException;

public class MultiIssuerJwtAuthHandler implements AuthenticationHandlerInternal {

  private static final Logger LOGGER = LogManager.getLogger(MultiIssuerJwtAuthHandler.class);


  private final JwksResolver jwksResolver;

  public MultiIssuerJwtAuthHandler(JwksResolver resolver) {
    this.jwksResolver = resolver;
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
    String token = BearerTokenExtractor.extract(ctx);
    if (token == null || token.isBlank()) {
      LOGGER.warn("Missing or invalid Authorization header");
      handler.handle(Future.failedFuture(new DxUnauthorizedException(AuthConstants.MISSING_BEARER_TOKEN)));
      return;
    }

    String issuer;
    String kid;
    try {
      issuer = JwtTokenUtil.extractIssuer(token);
      kid = JwtTokenUtil.extractKid(token);
    } catch (Exception e) {
      LOGGER.error("Failed to extract token claims: {}", e.getMessage());
      handler.handle(Future.failedFuture(new DxUnauthorizedException(AuthConstants.INVALID_TOKEN_FORMAT)));
      return;
    }

    jwksResolver
        .resolve(issuer, kid)
        .compose(jwtAuth -> jwtAuth.authenticate(new TokenCredentials(token)))
        .onSuccess(user -> {
          LOGGER.info("Authentication successful for issuer: {}, kid: {}", issuer, kid);
          handler.handle(Future.succeededFuture(user));
        })
        .onFailure(err -> {
          LOGGER.error("Authentication failed for issuer {}, kid {}: {}", issuer, kid, err.getMessage());
          handler.handle(Future.failedFuture(
              new DxUnauthorizedException(AuthConstants.UNAUTHORIZED.formatted(err.getMessage()))));
        });
  }
}
