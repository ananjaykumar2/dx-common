package org.cdpg.dx.auth.v2.handler;

import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authentication.TokenCredentials;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.impl.AuthenticationHandlerInternal;
import java.util.Objects;
import org.cdpg.dx.auth.authentication.client.JwksResolver;
import org.cdpg.dx.auth.authentication.util.JwtTokenUtil;
import org.cdpg.dx.auth.v2.resolver.AppCredentialsResolver;
import org.cdpg.dx.auth.v2.resolver.DelegationResolver;
import org.cdpg.dx.auth.v2.resolver.JwtPrincipalResolver;
import org.cdpg.dx.common.exception.DxBadRequestException;
import org.cdpg.dx.common.exception.DxUnauthorizedException;

/**
 * Self-contained v2 authentication entry point. Validates the JWT via {@link JwksResolver} and
 * dispatches to the appropriate principal resolver. Sets {@code ctx.user()} as a side-effect so
 * downstream code that reads {@code ctx.user().subject()} continues to work.
 *
 * <p>Dispatch rules, evaluated in order:
 *
 * <ol>
 *   <li>Both app credentials AND a Bearer token → 400 (ambiguous).
 *   <li>App-credential headers present → {@link AppCredentialsResolver}.
 *   <li>Bearer + {@code X-Delegator-Id} → JWT validation → {@link DelegationResolver}.
 *   <li>Bearer alone → JWT validation → {@link JwtPrincipalResolver}.
 *   <li>Otherwise → 401.
 * </ol>
 */
public final class AuthenticationHandlerV2 implements AuthenticationHandlerInternal {

  private final JwksResolver jwksResolver;
  private final JwtPrincipalResolver jwtResolver;
  private final DelegationResolver delegationResolver;
  private final AppCredentialsResolver appResolver;

  public AuthenticationHandlerV2(
      JwksResolver jwksResolver,
      JwtPrincipalResolver jwtResolver,
      DelegationResolver delegationResolver,
      AppCredentialsResolver appResolver) {
    this.jwksResolver = Objects.requireNonNull(jwksResolver, "jwksResolver");
    this.jwtResolver = Objects.requireNonNull(jwtResolver, "jwtResolver");
    this.delegationResolver = Objects.requireNonNull(delegationResolver, "delegationResolver");
    this.appResolver = Objects.requireNonNull(appResolver, "appResolver");
  }

  @Override
  public void handle(RoutingContext ctx) {
    String authHeader = ctx.request().getHeader("Authorization");
    String appIdHeader = ctx.request().getHeader("X-App-Id");
    String delegatorHeader = ctx.request().getHeader("X-Delegator-Id");

    boolean hasBearer = authHeader != null && authHeader.startsWith("Bearer ");
    boolean hasBasic = authHeader != null && authHeader.startsWith("Basic ");
    boolean hasAppHeader = appIdHeader != null && !appIdHeader.isBlank();

    boolean appPath = hasAppHeader || hasBasic;
    if (appPath && hasBearer) {
      ctx.fail(
          new DxBadRequestException(
              "Ambiguous credentials: send either JWT or app credentials, not both"));
      return;
    }

    if (appPath) {
      appResolver.resolve(ctx);
      return;
    }

    if (hasBearer) {
      String token = authHeader.substring(7).trim();
      validateAndDispatch(ctx, token, delegatorHeader);
      return;
    }

    ctx.fail(new DxUnauthorizedException("Missing credentials"));
  }

  private void validateAndDispatch(RoutingContext ctx, String token, String delegatorHeader) {
    String issuer;
    String kid;
    try {
      issuer = JwtTokenUtil.extractIssuer(token);
      kid = JwtTokenUtil.extractKid(token);
    } catch (Exception e) {
      ctx.fail(new DxUnauthorizedException("Invalid token format"));
      return;
    }

    jwksResolver
        .resolve(issuer, kid)
        .compose(jwtAuth -> jwtAuth.authenticate(new TokenCredentials(token)))
        .onSuccess(
            user -> {
              ctx.setUser(user);
              if (delegatorHeader != null && !delegatorHeader.isBlank()) {
                delegationResolver.resolve(ctx);
              } else {
                jwtResolver.resolve(ctx);
              }
            })
        .onFailure(
            err ->
                ctx.fail(
                    new DxUnauthorizedException("Unauthorized: %s".formatted(err.getMessage()))));
  }

  @Override
  public void authenticate(RoutingContext context, Handler<AsyncResult<User>> handler) {}
}
