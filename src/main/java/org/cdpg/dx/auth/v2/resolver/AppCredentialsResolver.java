package org.cdpg.dx.auth.v2.resolver;

import io.vertx.core.Future;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.web.RoutingContext;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.cdpg.dx.auth.appid.handler.AppIdAuthHandler;
import org.cdpg.dx.auth.v2.lookup.AppCredentialLookup;
import org.cdpg.dx.auth.v2.lookup.UserLookup;
import org.cdpg.dx.auth.v2.model.AppPrincipal;
import org.cdpg.dx.auth.v2.model.DxRole;
import org.cdpg.dx.auth.v2.model.UserSnapshot;
import org.cdpg.dx.auth.v2.registry.SystemRoleScopeMap;
import org.cdpg.dx.common.exception.DxForbiddenException;
import org.cdpg.dx.common.exception.DxUnauthorizedException;

/**
 * Resolves app credentials (either {@code X-App-Id} + {@code X-App-Secret} headers, or {@code
 * Authorization: Basic base64(appId:secret)}) into a Vert.x {@link User} stored via
 * {@code ctx.setUser()}.
 *
 * <p>The produced User principal contains:
 * <ul>
 *   <li>{@code sub} — owner's sub
 *   <li>{@code organisation_id} — owner's org
 *   <li>{@code realm_access.roles} — owner's current roles
 *   <li>{@code scopes} — intersection of app's stored scopes and owner's role-derived scopes
 *   <li>{@code app_id} — the app identifier (for auditing)
 * </ul>
 */
public final class AppCredentialsResolver {
  private static final Logger LOGGER = LogManager.getLogger(AppCredentialsResolver.class);

  private final AppCredentialLookup appLookup;
  private final UserLookup userLookup;

  public AppCredentialsResolver(AppCredentialLookup appLookup, UserLookup userLookup) {
    this.appLookup = Objects.requireNonNull(appLookup, "appLookup");
    this.userLookup = Objects.requireNonNull(userLookup, "userLookup");
  }

  /**
   * Authentication contract for Vert.x {@code ChainAuthHandler}: verifies app credentials and
   * returns a fully-built {@link User} via a {@link Future}. Does NOT touch the RoutingContext —
   * the caller ({@link org.cdpg.dx.auth.v2.handler.AuthenticationHandlerV2}) is responsible for
   * {@code ctx.setUser()} and moving {@link AppIdAuthHandler#PRINCIPAL_APP_ID_KEY} to context data.
   */
  public Future<User> authenticateForChain(RoutingContext ctx) {
    Credentials creds = extractCredentials(ctx);
    if (creds == null) {
      return Future.failedFuture(new DxUnauthorizedException("Missing app credentials"));
    }
    return appLookup.verify(creds.appId, creds.secret)
        .recover(err -> {
          LOGGER.error("App authentication service error: {}", err.getMessage());
          return Future.failedFuture(new DxUnauthorizedException("Authentication service error"));
        })
        .compose(maybeApp -> {
          if (maybeApp.isEmpty() || !maybeApp.get().active()) {
            return Future.failedFuture(new DxUnauthorizedException("Invalid app credentials"));
          }
          AppPrincipal app = maybeApp.get();
          LOGGER.info("App authentication successful for appId: {}, ownerSub: {}", app.appId(), app.ownerSub());
          return userLookup.findBySub(app.ownerSub())
              .recover(err -> {
                LOGGER.error("User lookup failed: {}", err.getMessage());
                return Future.failedFuture(new DxUnauthorizedException("User lookup failed"));
              })
              .compose(maybeOwner -> {
                if (maybeOwner.isEmpty() || maybeOwner.get().disabled()) {
                  return Future.failedFuture(new DxForbiddenException("App owner is no longer active"));
                }
                UserSnapshot owner = maybeOwner.get();
                LOGGER.info("App owner lookup successful for sub: {}, orgId: {}", owner.sub(), owner.organisationId());
                User user = buildUser(app, owner);
                // Stash appId for AuthenticationHandlerV2.postAuthentication() to move to ctx data
                user.principal().put(AppIdAuthHandler.PRINCIPAL_APP_ID_KEY, app.appId());
                LOGGER.debug("app user principal for chain auth: {}", user.principal());
                return Future.succeededFuture(user);
              });
        });
  }

  public void resolve(RoutingContext ctx) {
    Credentials creds = extractCredentials(ctx);
    if (creds == null) {
      ctx.fail(new DxUnauthorizedException("Missing app credentials"));
      return;
    }

    appLookup
        .verify(creds.appId, creds.secret)
        .onFailure(err -> ctx.fail(new DxUnauthorizedException("Authentication service error")))
        .onSuccess(
            maybeApp -> {
              if (maybeApp.isEmpty() || !maybeApp.get().active()) {
                ctx.fail(new DxUnauthorizedException("Invalid app credentials"));
                return;
              }
              AppPrincipal app = maybeApp.get();
              LOGGER.info(
                  "App authentication successful for appId: {}, ownerSub: {}",
                  app.appId(),
                  app.ownerSub());
              userLookup
                  .findBySub(app.ownerSub())
                  .onFailure(err -> ctx.fail(new DxUnauthorizedException("User lookup failed")))
                  .onSuccess(
                      maybeOwner -> {
                        if (maybeOwner.isEmpty() || maybeOwner.get().disabled()) {
                          ctx.fail(new DxForbiddenException("App owner is no longer active"));
                          return;
                        }
                        UserSnapshot owner = maybeOwner.get();
                        LOGGER.info(
                            "App owner lookup successful for sub: {}, orgId: {}",
                            owner.sub(),
                            owner.organisationId());
                        User user = buildUser(app, owner);
                        LOGGER.debug("app user principal: {}", user.principal());
                        ctx.setUser(user);
                        ctx.put(AppIdAuthHandler.APP_ID_KEY, app.appId());
                        ctx.next();
                      });
            });
  }

  private User buildUser(AppPrincipal app, UserSnapshot owner) {
    Set<String> ownerCurrentScopes = flatten(owner.roles());
    Set<String> capped = intersect(app.appScopes(), ownerCurrentScopes);

    String ownerOrgId = app.ownerOrgId() != null ? app.ownerOrgId() : owner.organisationId();

    JsonArray rolesArr = new JsonArray();
    owner.roles().forEach(r -> rolesArr.add(r.keycloakName()));

    JsonArray scopesArr = new JsonArray();
    capped.forEach(scopesArr::add);

    JsonObject principal = new JsonObject()
        .put("sub", owner.sub())
        .put("iss", "dx-controlplane")
        .put("organisation_id", ownerOrgId)
        .put("realm_access", new JsonObject().put("roles", rolesArr))
        .put("scopes", scopesArr)
        .put("app_id", app.appId());

    return User.create(principal);
  }

  private static Set<String> flatten(Set<DxRole> roles) {
    Set<String> out = new HashSet<>();
    for (DxRole r : roles) out.addAll(SystemRoleScopeMap.getScopes(r));
    return out;
  }

  private static Set<String> intersect(Iterable<String> a, Set<String> b) {
    Set<String> out = new HashSet<>();
    for (String s : a) if (b.contains(s)) out.add(s);
    return out;
  }

  /** Prefers {@code X-App-Id}/{@code X-App-Secret}; falls back to {@code Authorization: Basic}. */
  static Credentials extractCredentials(RoutingContext ctx) {
    String appId = ctx.request().getHeader("X-App-Id");
    String secret = ctx.request().getHeader("X-App-Secret");
    if (appId != null && secret != null && !appId.isBlank() && !secret.isBlank()) {
      return new Credentials(appId, secret);
    }

    String auth = ctx.request().getHeader("Authorization");
    if (auth == null || !auth.startsWith("Basic ")) return null;
    try {
      String decoded =
          new String(Base64.getDecoder().decode(auth.substring(6).trim()), StandardCharsets.UTF_8);
      int i = decoded.indexOf(':');
      if (i <= 0 || i == decoded.length() - 1) return null;
      return new Credentials(decoded.substring(0, i), decoded.substring(i + 1));
    } catch (IllegalArgumentException e) {
      return null;
    }
  }

  record Credentials(String appId, String secret) {}
}