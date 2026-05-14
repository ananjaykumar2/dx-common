package org.cdpg.dx.auth.authorization.handler;

import io.vertx.core.Handler;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.web.RoutingContext;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.cdpg.dx.auth.authentication.handler.AuthenticationHandler;
import org.cdpg.dx.auth.authorization.model.AuthorizationContext;
import org.cdpg.dx.auth.authorization.model.ScopeRule;
import org.cdpg.dx.common.exception.DxForbiddenException;
import org.cdpg.dx.common.exception.DxUnauthorizedException;
import org.cdpg.dx.auth.model.DxRole;

/**
 * Authorization entry point. All methods are static — this class has no state.
 * Reads the Vert.x {@link User} set by {@link AuthenticationHandler} and enforces scope
 * or role requirements.
 *
 * <p>All three auth paths (plain JWT, delegation, app credentials) pre-compute a {@code "scopes"}
 * array in the User principal, so {@link #forScopes} works uniformly across all of them.
 *
 * <p>Usage at route level:
 * <pre>
 *   router.get("/api/data")
 *       .handler(authHandler)
 *       .handler(AuthorizationHandler.forScopes(Scopes.DATA_ACCESS))
 *       .handler(myService::handle);
 * </pre>
 */
public final class AuthorizationHandler {

  private static final Logger LOGGER = LogManager.getLogger(AuthorizationHandler.class);

  /**
   * @deprecated No longer populated. All auth paths now set {@code ctx.user()} directly.
   */
  @Deprecated
  public static final String PRINCIPAL_KEY = "dxPrincipal";

  private AuthorizationHandler() {}

  /**
   * Passes if the user's pre-computed {@code "scopes"} contain <em>any</em> of the required
   * scopes. Works uniformly for plain JWT, delegation, and app-credential users.
   */
  public static Handler<RoutingContext> forScopes(String... required) {
    Objects.requireNonNull(required, "required");
    if (required.length == 0) throw new IllegalArgumentException("forScopes requires at least one scope");

    Set<String> requiredSet = new HashSet<>(Arrays.asList(required));

    return ctx -> {
      User user = getUser(ctx);
      if (user == null) return;

      JsonArray scopes = user.principal().getJsonArray("scopes", new JsonArray());
      LOGGER.debug("Effective scopes: {}", scopes);

      boolean match = scopes.stream()
          .map(Object::toString)
          .anyMatch(requiredSet::contains);

      if (match) {
        ctx.next();
      } else {
        ctx.fail(new DxForbiddenException("Insufficient scope"));
      }
    };
  }

  /**
   * Passes if the user's {@code realm_access.roles} contain <em>any</em> of the required roles.
   */
  public static Handler<RoutingContext> forRoles(DxRole... required) {
    Objects.requireNonNull(required, "required");
    if (required.length == 0) throw new IllegalArgumentException("forRoles requires at least one role");

    Set<String> requiredNames = Arrays.stream(required)
        .map(DxRole::value)
        .collect(Collectors.toSet());

    return ctx -> {
      User user = getUser(ctx);
      if (user == null) return;

      JsonArray roles = user.principal()
          .getJsonObject("realm_access", new JsonObject())
          .getJsonArray("roles", new JsonArray());

      boolean match = roles.stream()
          .map(Object::toString)
          .anyMatch(requiredNames::contains);

      if (match) {
        ctx.next();
      } else {
        ctx.fail(new DxForbiddenException("User does not hold the required role"));
      }
    };
  }

  /**
   * Walks rules in order — highest authority first (PLATFORM → ORG → SELF). The first matching
   * rule wins and publishes an {@link AuthorizationContext} at {@link AuthorizationContext#KEY}.
   */
  public static Handler<RoutingContext> forScopesWithContext(ScopeRule... rules) {
    Objects.requireNonNull(rules, "rules");
    if (rules.length == 0) throw new IllegalArgumentException("forScopesWithContext requires at least one rule");

    return ctx -> {
      User user = getUser(ctx);
      if (user == null) return;

      JsonObject principal = user.principal();
      JsonArray scopesArr = principal.getJsonArray("scopes", new JsonArray());
      Set<String> effectiveScopes = scopesArr.stream()
          .map(Object::toString)
          .collect(Collectors.toSet());

      String sub   = principal.getString("sub");
      String orgId = principal.getString("organisation_id");

      for (ScopeRule rule : rules) {
        if (effectiveScopes.contains(rule.scope())) {
          AuthorizationContext authCtx = switch (rule.level()) {
            case PLATFORM -> AuthorizationContext.platform(rule.scope());
            case ORG      -> AuthorizationContext.org(rule.scope(), orgId);
            case SELF     -> AuthorizationContext.self(rule.scope(), sub);
          };
          ctx.put(AuthorizationContext.KEY, authCtx);
          ctx.next();
          return;
        }
      }
      ctx.fail(new DxForbiddenException("Insufficient scope"));
    };
  }

  /** Passes immediately when {@code isKycRequired} is false. Otherwise verifies the
   * {@code kyc_verified} claim in the user principal. */
  public static Handler<RoutingContext> kycVerification(boolean isKycRequired) {
    if (!isKycRequired) {
      return RoutingContext::next;
    }
    return ctx -> {
      User user = getUser(ctx);
      if (user == null) return;
      JsonObject principal = user.principal();
      if (!principal.containsKey("kyc_verified")) {
        ctx.fail(new DxForbiddenException("Missing KYC verification status."));
        return;
      }
      if (!principal.getBoolean("kyc_verified", false)) {
        ctx.fail(new DxForbiddenException("User's KYC is not verified."));
        return;
      }
      ctx.next();
    };
  }

  private static User getUser(RoutingContext ctx) {
    User user = ctx.user();
    if (user == null) {
      ctx.fail(new DxUnauthorizedException("No authenticated user"));
      return null;
    }
    LOGGER.debug("Authenticated user principal: {}", user.principal());
    return user;
  }
}