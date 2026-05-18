package org.cdpg.dx.auth.authentication.handler;

import io.vertx.ext.auth.authentication.TokenCredentials;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.AuthenticationHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.cdpg.dx.auth.authentication.client.JwksResolver;
import org.cdpg.dx.auth.authentication.util.BearerTokenExtractor;
import org.cdpg.dx.auth.authentication.util.JwtTokenUtil;
import org.cdpg.dx.auth.common.AuthConstants;
import org.cdpg.dx.common.exception.DxUnauthorizedException;

public class OptionalMultiIssuerJwtAuthHandler implements AuthenticationHandler {

  private static final Logger LOGGER = LogManager.getLogger(OptionalMultiIssuerJwtAuthHandler.class);

  private final JwksResolver jwksResolver;

  public OptionalMultiIssuerJwtAuthHandler(JwksResolver resolver) {
    this.jwksResolver = resolver;
  }

  @Override
  public void handle(RoutingContext ctx) {
    String token = BearerTokenExtractor.extract(ctx);
    if (token == null || token.isBlank()) {
      LOGGER.warn("Missing or invalid Authorization header");
      ctx.next();
      return;
    }

    String issuer;
    String kid;
    try {
      issuer = JwtTokenUtil.extractIssuer(token);
      kid = JwtTokenUtil.extractKid(token);
    } catch (Exception e) {
      LOGGER.error("Failed to extract token claims: {}", e.getMessage());
      ctx.fail(new DxUnauthorizedException(AuthConstants.INVALID_TOKEN_FORMAT));
      return;
    }

    jwksResolver
        .resolve(issuer, kid)
        .compose(jwtAuth -> jwtAuth.authenticate(new TokenCredentials(token)))
        .onSuccess(user -> {
          LOGGER.info("Authentication successful for issuer: {}, kid: {}", issuer, kid);
          ctx.setUser(user);
          ctx.next();
        })
        .onFailure(err -> {
          LOGGER.error("Authentication failed for issuer {}, kid {}: {}", issuer, kid, err.getMessage());
          ctx.fail(new DxUnauthorizedException(AuthConstants.UNAUTHORIZED.formatted(err.getMessage())));
        });
  }
}
