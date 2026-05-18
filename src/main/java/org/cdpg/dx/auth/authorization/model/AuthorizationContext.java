package org.cdpg.dx.auth.authorization.model;

import org.cdpg.dx.auth.authorization.handler.AuthorizationHandler;

import java.util.Objects;

/**
 * Set on the routing context by {@link AuthorizationHandler#forScopesWithContext(ScopeRule...)} on
 * a successful match. Services read it to apply the correct data boundary for the matched tier.
 *
 * <p>Controllers should pass this through to the service layer; branching on {@code level} belongs
 * in the service, not the controller.
 */
public final class AuthorizationContext {

  /** Routing-context key under which {@link AuthorizationHandler} publishes this object. */
  public static final String KEY = "authContext";

  private final AuthLevel level;
  private final String scope;
  private final String orgId;
  private final String sub;

  private AuthorizationContext(AuthLevel level, String scope, String orgId, String sub) {
    this.level = Objects.requireNonNull(level, "level");
    this.scope = Objects.requireNonNull(scope, "scope");
    this.orgId = orgId;
    this.sub = sub;
  }

  public static AuthorizationContext platform(String scope) {
    return new AuthorizationContext(AuthLevel.PLATFORM, scope, null, null);
  }

  public static AuthorizationContext org(String scope, String orgId) {
    return new AuthorizationContext(AuthLevel.ORG, scope, orgId, null);
  }

  public static AuthorizationContext self(String scope, String sub) {
    return new AuthorizationContext(AuthLevel.SELF, scope, null, sub);
  }

  public AuthLevel getLevel() {
    return level;
  }

  public String getScope() {
    return scope;
  }

  /** Only set when {@link #getLevel()} is {@link AuthLevel#ORG}. */
  public String getOrgId() {
    return orgId;
  }

  /** Only set when {@link #getLevel()} is {@link AuthLevel#SELF}. */
  public String getSub() {
    return sub;
  }
}
