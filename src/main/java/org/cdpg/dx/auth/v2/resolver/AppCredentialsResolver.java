package org.cdpg.dx.auth.v2.resolver;

import io.vertx.ext.web.RoutingContext;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.cdpg.dx.auth.v2.handler.AuthorizationHandler;
import org.cdpg.dx.auth.v2.lookup.AppCredentialLookup;
import org.cdpg.dx.auth.v2.lookup.UserLookup;
import org.cdpg.dx.auth.v2.model.AppPrincipal;
import org.cdpg.dx.auth.v2.model.DxPrincipal;
import org.cdpg.dx.auth.v2.model.DxRole;
import org.cdpg.dx.auth.v2.model.UserSnapshot;
import org.cdpg.dx.auth.v2.registry.SystemRoleScopeMap;
import org.cdpg.dx.common.exception.DxForbiddenException;
import org.cdpg.dx.common.exception.DxUnauthorizedException;

/**
 * Resolves app credentials (either {@code X-App-Id} + {@code X-App-Secret} headers, or {@code
 * Authorization: Basic base64(appId:secret)}) into a {@link DxPrincipal}.
 *
 * <p>Depends only on {@link AppCredentialLookup} and {@link UserLookup}; transport (local vs gRPC)
 * is the implementation's concern.
 *
 * <p>Effective scopes are the intersection of the app's stored scopes and the owner's current
 * role-derived scopes — so revoking a role from the owner immediately shrinks the app's authority.
 */
public final class AppCredentialsResolver {
  private static final Logger LOGGER = LogManager.getLogger(AppCredentialsResolver.class);

  private final AppCredentialLookup appLookup;
  private final UserLookup userLookup;

  public AppCredentialsResolver(AppCredentialLookup appLookup, UserLookup userLookup) {
    this.appLookup = Objects.requireNonNull(appLookup, "appLookup");
    this.userLookup = Objects.requireNonNull(userLookup, "userLookup");
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
                        DxPrincipal principal = buildPrincipal(app, owner);
                        LOGGER.debug("dxPrincipal : " + principal.toJson());
                        ctx.put(AuthorizationHandler.PRINCIPAL_KEY, principal);
                        ctx.next();
                      });
            });
  }

  private DxPrincipal buildPrincipal(AppPrincipal app, UserSnapshot owner) {
    Set<String> ownerCurrentScopes = flatten(owner.roles());
    Set<String> capped = intersect(app.appScopes(), ownerCurrentScopes);

    String ownerOrgId = app.ownerOrgId() != null ? app.ownerOrgId() : owner.organisationId();

    return DxPrincipal.builder()
        .authenticatedSub(owner.sub())
        .authenticatedOrgId(ownerOrgId)
        .directScopes(capped)
        .auditRoles(owner.roles())
        .appId(app.appId())
        .build();
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
