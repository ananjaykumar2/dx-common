package org.cdpg.dx.auth.v2.handler;

import io.vertx.core.AsyncResult;
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
import org.cdpg.dx.auth.authentication.client.JwksResolver;
import org.cdpg.dx.auth.authentication.util.JwtTokenUtil;
import org.cdpg.dx.auth.v2.model.DxRole;
import org.cdpg.dx.auth.v2.registry.SystemRoleScopeMap;
import org.cdpg.dx.auth.v2.resolver.AppCredentialsResolver;
import org.cdpg.dx.auth.v2.resolver.DelegationResolver;
import org.cdpg.dx.common.exception.DxBadRequestException;
import org.cdpg.dx.common.exception.DxUnauthorizedException;

/**
 * Self-contained v2 authentication entry point. Validates the JWT via {@link JwksResolver} and
 * dispatches to the appropriate resolver. Sets {@code ctx.user()} on every successful path so
 * downstream code reads a uniform Vert.x {@link User} regardless of auth type.
 *
 * <p>For plain JWT users, roles from {@code realm_access.roles} are flattened to scopes via
 * {@link SystemRoleScopeMap} and stored under the {@code "scopes"} key in the User principal.
 * Delegation and app paths compute capped scopes themselves and also store under {@code "scopes"}.
 *
 * <p>Dispatch rules, evaluated in order:
 *
 * <ol>
 *   <li>Both app credentials AND a Bearer token → 400 (ambiguous).
 *   <li>App-credential headers present → {@link AppCredentialsResolver}.
 *   <li>Bearer + {@code delegatorId} → JWT validation → {@link DelegationResolver}.
 *   <li>Bearer alone → JWT validation → scope enrichment → {@code ctx.next()}.
 *   <li>Otherwise → 401.
 * </ol>
 */
public final class AuthenticationHandlerV2 implements AuthenticationHandlerInternal {

  private final JwksResolver jwksResolver;
  private final DelegationResolver delegationResolver;
  private final AppCredentialsResolver appResolver;

  public AuthenticationHandlerV2(
      JwksResolver jwksResolver,
      DelegationResolver delegationResolver,
      AppCredentialsResolver appResolver) {
    this.jwksResolver = Objects.requireNonNull(jwksResolver, "jwksResolver");
    this.delegationResolver = Objects.requireNonNull(delegationResolver, "delegationResolver");
    this.appResolver = Objects.requireNonNull(appResolver, "appResolver");
  }

  @Override
  public void handle(RoutingContext ctx) {
    String authHeader = ctx.request().getHeader("Authorization");
    String delegatorHeader = ctx.request().getHeader("did");

    boolean hasBearer = authHeader != null && authHeader.startsWith("Bearer ");
    boolean hasBasic = authHeader != null && authHeader.startsWith("Basic ");

    if (hasBasic && hasBearer) {
      ctx.fail(
          new DxBadRequestException(
              "Ambiguous credentials: send either JWT or app credentials, not both"));
      return;
    }

    if (hasBasic) {
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
              User enriched = enrichWithScopes(user);
              ctx.setUser(enriched);
              if (delegatorHeader != null && !delegatorHeader.isBlank()) {
                delegationResolver.resolve(ctx);
              } else {
                ctx.next();
              }
            })
        .onFailure(
            err ->
                ctx.fail(
                    new DxUnauthorizedException("Unauthorized: %s".formatted(err.getMessage()))));
  }

  /**
   * Flattens {@code realm_access.roles} from the JWT principal into pre-computed scopes and
   * returns a new User with the {@code "scopes"} key added. All original JWT claims are preserved.
   */
  private static User enrichWithScopes(User jwtUser) {
    JsonObject principal = jwtUser.principal().copy();
    JsonArray roles = principal
        .getJsonObject("realm_access", new JsonObject())
        .getJsonArray("roles", new JsonArray());

    Set<String> scopeSet = new HashSet<>();
    for (Object r : roles) {
      DxRole.fromKeycloakName(r.toString())
            .ifPresent(role -> scopeSet.addAll(SystemRoleScopeMap.getScopes(role)));
    }

    JsonArray scopesArr = new JsonArray();
    scopeSet.forEach(scopesArr::add);
    principal.put("scopes", scopesArr);

    return User.create(principal);
  }

  @Override
  public void authenticate(RoutingContext context, Handler<AsyncResult<User>> handler) {}
}