package org.cdpg.dx.auth.authentication.handler;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authentication.TokenCredentials;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.impl.AuthenticationHandlerInternal;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import org.cdpg.dx.auth.appid.handler.AppIdAuthHandler;
import org.cdpg.dx.auth.authentication.client.JwksResolver;
import org.cdpg.dx.auth.authentication.util.JwtTokenUtil;
import org.cdpg.dx.auth.model.DxRole;
import org.cdpg.dx.auth.authorization.registry.SystemRoleScopeMap;
import org.cdpg.dx.auth.authentication.resolver.AppCredentialsResolver;
import org.cdpg.dx.auth.authentication.resolver.DelegationResolver;
import org.cdpg.dx.common.exception.DxBadRequestException;
import org.cdpg.dx.common.exception.DxUnauthorizedException;

/**
 * Self-contained authentication entry point. Validates the JWT via {@link JwksResolver} and
 * dispatches to the appropriate resolver. Sets {@code ctx.user()} on every successful path so
 * downstream code reads a uniform Vert.x {@link User} regardless of auth type.
 *
 * <p>For plain JWT users, roles from {@code realm_access.roles} are flattened to scopes via {@link
 * SystemRoleScopeMap} and stored under the {@code "scopes"} key in the User principal. Delegation
 * and app paths compute capped scopes themselves and also store under {@code "scopes"}.
 *
 * <p>Dispatch rules, evaluated in order:
 *
 * <ol>
 *   <li>Both app credentials AND a Bearer token → 400 (ambiguous).
 *   <li>App-credential headers present → {@link AppCredentialsResolver#authenticateForChain}.
 *   <li>Bearer + {@code did} → JWT validation → {@link DelegationResolver} (via
 *       postAuthentication).
 *   <li>Bearer alone → JWT validation → scope enrichment → {@code ctx.next()}.
 *   <li>Otherwise → 401.
 * </ol>
 *
 * <p>Implements {@link AuthenticationHandlerInternal} so Vert.x {@code RouterBuilder} security
 * chains ({@code ChainAuthHandler.any()}) can call {@link #authenticate} correctly.
 */
public final class AuthenticationHandler implements AuthenticationHandlerInternal {

  private final JwksResolver jwksResolver;
  private final DelegationResolver delegationResolver;
  private final AppCredentialsResolver appResolver;

  public AuthenticationHandler(
      JwksResolver jwksResolver,
      DelegationResolver delegationResolver,
      AppCredentialsResolver appResolver) {
    this.jwksResolver = Objects.requireNonNull(jwksResolver, "jwksResolver");
    this.delegationResolver = Objects.requireNonNull(delegationResolver, "delegationResolver");
    this.appResolver = Objects.requireNonNull(appResolver, "appResolver");
  }

  /**
   * Standard Vert.x handler entry point — delegates to {@link #authenticate} then calls {@link
   * #postAuthentication} on success. This path is used when the handler is invoked directly (not
   * via {@code ChainAuthHandler}).
   */
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

  /**
   * Authentication contract for {@code ChainAuthHandler}: resolves credentials and calls {@code
   * handler} with the resulting {@link User} (success) or the cause (failure). Must NOT call {@code
   * ctx.setUser()}, {@code ctx.next()}, or {@code ctx.fail()} directly.
   */
  @Override
  public void authenticate(RoutingContext ctx, Handler<AsyncResult<User>> handler) {
    String authHeader = ctx.request().getHeader("Authorization");
    String delegatorHeader = ctx.request().getHeader("did");

    boolean hasBearer = authHeader != null && authHeader.startsWith("Bearer ");
    boolean hasBasic = authHeader != null && authHeader.startsWith("Basic ");

    if (hasBasic && hasBearer) {
      handler.handle(
          Future.failedFuture(
              new DxBadRequestException(
                  "Ambiguous credentials: send either JWT or app credentials, not both")));
      return;
    }

    if (hasBasic) {
      appResolver
          .authenticateForChain(ctx)
          .onSuccess(user -> handler.handle(Future.succeededFuture(user)))
          .onFailure(err -> handler.handle(Future.failedFuture(err)));
      return;
    }

    if (hasBearer) {
      String token = authHeader.substring(7).trim();
      authenticateBearer(token, delegatorHeader, handler);
      return;
    }

    handler.handle(Future.failedFuture(new DxUnauthorizedException("Missing credentials")));
  }

  /**
   * Called after {@link #authenticate} succeeds and {@code ctx.setUser()} has been called. Moves
   * the {@code _appId} stash from the principal to routing-context data, and dispatches delegation
   * resolution when a {@code did} header was present.
   */
  @Override
  public void postAuthentication(RoutingContext ctx) {
    // AppId path: move _appId from principal to ctx routing-context data
    String appId = ctx.user().principal().getString(AppIdAuthHandler.PRINCIPAL_APP_ID_KEY);
    if (appId != null) {
      ctx.put(AppIdAuthHandler.APP_ID_KEY, appId);
      ctx.user().principal().remove(AppIdAuthHandler.PRINCIPAL_APP_ID_KEY);
    }

    // JWT delegation path: stashed by authenticateBearer()
    String delegatorHeader = ctx.user().principal().getString("_delegatorHeader");
    if (delegatorHeader != null) {
      ctx.user().principal().remove("_delegatorHeader");
      delegationResolver.resolve(ctx); // async — calls ctx.next() or ctx.fail()
      return;
    }

    ctx.next();
  }

  private void authenticateBearer(
      String token, String delegatorHeader, Handler<AsyncResult<User>> handler) {
    String issuer;
    String kid;
    try {
      issuer = JwtTokenUtil.extractIssuer(token);
      kid = JwtTokenUtil.extractKid(token);
    } catch (Exception e) {
      handler.handle(Future.failedFuture(new DxUnauthorizedException("Invalid token format")));
      return;
    }

    jwksResolver
        .resolve(issuer, kid)
        .compose(jwtAuth -> jwtAuth.authenticate(new TokenCredentials(token)))
        .onSuccess(
            user -> {
              User enriched = enrichWithScopes(user);
              // Stash the delegator header for postAuthentication() to pick up
              if (delegatorHeader != null && !delegatorHeader.isBlank()) {
                enriched.principal().put("_delegatorHeader", delegatorHeader);
              }
              handler.handle(Future.succeededFuture(enriched));
            })
        .onFailure(
            err ->
                handler.handle(
                    Future.failedFuture(
                        new DxUnauthorizedException(
                            "Unauthorized: %s".formatted(err.getMessage())))));
  }

  /**
   * Flattens {@code realm_access.roles} from the JWT principal into pre-computed scopes and returns
   * a new User with the {@code "scopes"} key added. All original JWT claims are preserved.
   */
  private static User enrichWithScopes(User jwtUser) {
    JsonObject principal = jwtUser.principal().copy();
    JsonArray roles =
        principal
            .getJsonObject("realm_access", new JsonObject())
            .getJsonArray("roles", new JsonArray());

    Set<String> scopeSet = new HashSet<>();
    for (Object r : roles) {
      DxRole.fromString(r.toString())
          .ifPresent(role -> scopeSet.addAll(SystemRoleScopeMap.getScopes(role)));
    }

    JsonArray scopesArr = new JsonArray();
    scopeSet.forEach(scopesArr::add);
    principal.put("scopes", scopesArr);

    return User.create(principal);
  }
}
