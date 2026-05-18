package org.cdpg.dx.auth.authorization.model;

import org.cdpg.dx.auth.authorization.handler.AuthorizationHandler;

import java.util.Objects;

/**
 * A single "tier rule" for {@link AuthorizationHandler#forScopesWithContext(ScopeRule...)}.
 *
 * <p>Rules are evaluated in the order provided — the first rule whose scope is present in the
 * principal's effective scope set wins, and its {@link AuthLevel} is attached to the routing
 * context for the service to read. Put highest authority (PLATFORM) first.
 */
public final class ScopeRule {

  private final AuthLevel level;
  private final String scope;

  private ScopeRule(AuthLevel level, String scope) {
    this.level = Objects.requireNonNull(level, "level");
    this.scope = Objects.requireNonNull(scope, "scope");
  }

  public static ScopeRule platform(String scope) {
    return new ScopeRule(AuthLevel.PLATFORM, scope);
  }

  public static ScopeRule org(String scope) {
    return new ScopeRule(AuthLevel.ORG, scope);
  }

  public static ScopeRule self(String scope) {
    return new ScopeRule(AuthLevel.SELF, scope);
  }

  public AuthLevel level() {
    return level;
  }

  public String scope() {
    return scope;
  }
}