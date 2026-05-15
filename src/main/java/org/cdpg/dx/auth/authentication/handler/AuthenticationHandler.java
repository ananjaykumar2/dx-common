package org.cdpg.dx.auth.authentication.handler;

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
import java.util.Objects;
import org.cdpg.dx.auth.appid.handler.AppIdAuthHandler;
import org.cdpg.dx.auth.authentication.resolver.AppCredentialsResolver;
import org.cdpg.dx.auth.authentication.resolver.DelegationResolver;
import org.cdpg.dx.auth.authentication.resolver.JwtResolver;
import org.cdpg.dx.common.exception.DxBadRequestException;
import org.cdpg.dx.common.exception.DxUnauthorizedException;
import org.cdpg.dx.common.model.DxUser;

/**
 * Authentication entry point. Dispatches to the appropriate resolver based on credentials and sets
 * {@code ctx.user()} on every successful path.
 *
 * <p>Dispatch rules:
 *
 * <ol>
 *   <li>Basic + Bearer → 400 (ambiguous)
 *   <li>Basic/app headers → {@link AppCredentialsResolver#resolve} → {@link #toVertxUser}
 *   <li>Bearer + {@code did} → {@link JwtResolver#resolve} → {@link DelegationResolver#resolve} →
 *       {@link #toVertxUser}
 *   <li>Bearer alone → {@link JwtResolver#resolve}
 *   <li>Otherwise → 401
 * </ol>
 */
public final class AuthenticationHandler implements AuthenticationHandlerInternal {

  private final JwtResolver jwtResolver;
  private final DelegationResolver delegationResolver;
  private final AppCredentialsResolver appCredentialsResolver;

  public AuthenticationHandler(
      JwtResolver jwtResolver,
      DelegationResolver delegationResolver,
      AppCredentialsResolver appCredentialsResolver) {
    this.jwtResolver = Objects.requireNonNull(jwtResolver, "jwtResolver");
    this.delegationResolver = Objects.requireNonNull(delegationResolver, "delegationResolver");
    this.appCredentialsResolver =
        Objects.requireNonNull(appCredentialsResolver, "appCredentialsResolver");
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
    String authHeader = ctx.request().getHeader("Authorization");

    boolean hasBearer = authHeader != null && authHeader.startsWith("Bearer ");
    boolean hasBasic = authHeader != null && authHeader.startsWith("Basic ");

    if (hasBasic) {
      String[] creds = extractBasicCredentials(authHeader);
      if (creds == null) {
        handler.handle(
            Future.failedFuture(new DxUnauthorizedException("Invalid Basic credentials")));
        return;
      }
      appCredentialsResolver
          .resolve(creds[0], creds[1])
          .map(AuthenticationHandler::toVertxUser)
          .onSuccess(user -> handler.handle(Future.succeededFuture(user)))
          .onFailure(err -> handler.handle(Future.failedFuture(err)));
      return;
    }

    if (hasBearer) {
      String token = authHeader.substring(7).trim();
      String did = ctx.request().getHeader("did");
      jwtResolver
          .resolve(token)
          .onSuccess(
              user -> {
                if (did != null && !did.isBlank()) handler.handle(Future.succeededFuture(user));
              })
          .onFailure(err -> handler.handle(Future.failedFuture(err)));
      return;
    }

    handler.handle(Future.failedFuture(new DxUnauthorizedException("Missing credentials")));
  }

  @Override
  public void postAuthentication(RoutingContext ctx) {
    // App credentials: stash appId from principal to ctx routing data
    String appId = ctx.user().principal().getString("app_id");
    if (appId != null) {
      ctx.put(AppIdAuthHandler.APP_ID_KEY, appId);
    }

    // Delegation: JWT was validated, now resolve delegated identity
    String delegatorSub = ctx.user().principal().getString("_delegatorHeader");
    if (delegatorSub != null) {
      ctx.user().principal().remove("_delegatorHeader");
      String delegateeSub = ctx.user().principal().getString("sub");
      delegationResolver
          .resolve(delegatorSub, delegateeSub)
          .map(AuthenticationHandler::toVertxUser)
          .onSuccess(
              user -> {
                ctx.setUser(user);
                ctx.next();
              })
          .onFailure(ctx::fail);
      return;
    }

    ctx.next();
  }

  /** Converts a {@link DxUser} (with pre-computed capped scopes) into a Vert.x {@link User}. */
  static User toVertxUser(DxUser user) {
    JsonObject principal =
        new JsonObject()
            .put("sub", user.sub() != null ? user.sub().toString() : null)
            .put("organisation_id", user.organisationId())
            .put("kyc_verified", user.kycVerified())
            .put("email_verified", user.emailVerified())
            .put(
                "realm_access",
                new JsonObject()
                    .put(
                        "roles",
                        user.roles() != null ? new JsonArray(user.roles()) : new JsonArray()))
            .put("scopes", user.scopes() != null ? user.scopes() : new JsonArray());
    if (user.delegateeId() != null) {
      principal.put("delegatee_sub", user.delegateeId());
    }
    if (user.appId() != null) {
      principal.put("app_id", user.appId());
    }
    return User.create(principal);
  }

  /** Extracts {@code appId:secret} from an {@code Authorization: Basic ...} header. */
  private static String[] extractBasicCredentials(String authHeader) {
    try {
      String decoded =
          new String(
              Base64.getDecoder().decode(authHeader.substring(6).trim()), StandardCharsets.UTF_8);
      int i = decoded.indexOf(':');
      if (i <= 0 || i == decoded.length() - 1) return null;
      return new String[] {decoded.substring(0, i), decoded.substring(i + 1)};
    } catch (IllegalArgumentException e) {
      return null;
    }
  }
}
