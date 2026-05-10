package org.cdpg.dx.auth.v2.handler;

import io.vertx.core.Handler;
import io.vertx.ext.web.RoutingContext;
import java.util.Objects;
import java.util.Set;
import org.cdpg.dx.auth.v2.model.DxPrincipal;
import org.cdpg.dx.auth.v2.model.DxRole;
import org.cdpg.dx.auth.v2.registry.RoleScopeRegistry;
import org.cdpg.dx.common.exception.DxForbiddenException;
import org.cdpg.dx.common.exception.DxUnauthorizedException;

/**
 * Authorization entry point. Produces route-level handlers that read a {@link DxPrincipal} from the
 * routing context and enforce scope (or role) requirements.
 *
 * <p>Reads the principal at context key {@link #PRINCIPAL_KEY}. Callers must ensure an upstream
 * authentication step has populated it (e.g. {@link AuthenticationHandlerV2}).
 *
 * <p>Path-agnostic by design — the same handler runs for plain-user, delegation, and app principals
 * because effective scope resolution is uniform.
 */
public final class AuthorizationHandler {

  /** Routing-context key under which {@link AuthenticationHandlerV2} publishes the principal. */
  public static final String PRINCIPAL_KEY = "dxPrincipal";

  private final RoleScopeRegistry registry;

  public AuthorizationHandler(RoleScopeRegistry registry) {
    this.registry = Objects.requireNonNull(registry, "registry");
  }

  /** Passes if the principal's effective scopes contain <em>any</em> of the required scopes. */
  public Handler<RoutingContext> forScopes(String... required) {
    Objects.requireNonNull(required, "required");
    if (required.length == 0) {
      throw new IllegalArgumentException("forScopes requires at least one scope");
    }
    return ctx -> {
      DxPrincipal principal = getPrincipal(ctx);
      if (principal == null) {
        return;
      }
      Set<String> effective = registry.resolveEffectiveScopes(principal);
      for (String req : required) {
        if (effective.contains(req)) {
          ctx.next();
          return;
        }
      }
      ctx.fail(new DxForbiddenException("Insufficient scope"));
    };
  }

  /**
   * Walks rules in the given order — highest authority first (PLATFORM → ORG → SELF). The first
   * matching rule wins and publishes an {@link AuthorizationContext} at {@link
   * AuthorizationContext#KEY} for services to branch on.
   */
  public Handler<RoutingContext> forScopesWithContext(ScopeRule... rules) {
    Objects.requireNonNull(rules, "rules");
    if (rules.length == 0) {
      throw new IllegalArgumentException("forScopesWithContext requires at least one rule");
    }
    return ctx -> {
      DxPrincipal principal = getPrincipal(ctx);
      if (principal == null) {
        return;
      }
      Set<String> effective = registry.resolveEffectiveScopes(principal);
      for (ScopeRule rule : rules) {
        if (effective.contains(rule.scope())) {
          AuthorizationContext authCtx =
              switch (rule.level()) {
                case PLATFORM -> AuthorizationContext.platform(rule.scope());
                case ORG -> AuthorizationContext.org(rule.scope(), principal.getOrganisationId());
                case SELF -> AuthorizationContext.self(rule.scope(), principal.getSub());
              };
          ctx.put(AuthorizationContext.KEY, authCtx);
          ctx.next();
          return;
        }
      }
      ctx.fail(new DxForbiddenException("Insufficient scope"));
    };
  }

  /**
   * Identity gate. Passes if the principal holds any of the required roles (via {@code
   * authorizationRoles} for plain users, or via {@code auditRoles} for delegation/app principals —
   * the underlying identity is the same). Use sparingly; prefer {@link #forScopes}.
   */
  public Handler<RoutingContext> forRoles(DxRole... required) {
    Objects.requireNonNull(required, "required");
    if (required.length == 0) {
      throw new IllegalArgumentException("forRoles requires at least one role");
    }
    return ctx -> {
      DxPrincipal principal = getPrincipal(ctx);
      if (principal == null) {
        return;
      }
      Set<DxRole> roles =
          principal.isDirectUser() ? principal.getAuthorizationRoles() : principal.getAuditRoles();
      for (DxRole req : required) {
        if (roles.contains(req)) {
          ctx.next();
          return;
        }
      }
      ctx.fail(new DxForbiddenException("User does not hold the required role"));
    };
  }

  private DxPrincipal getPrincipal(RoutingContext ctx) {
    DxPrincipal principal = ctx.get(PRINCIPAL_KEY);
    if (principal == null) {
      ctx.fail(new DxUnauthorizedException("No authenticated principal"));
      return null;
    }
    return principal;
  }
}
