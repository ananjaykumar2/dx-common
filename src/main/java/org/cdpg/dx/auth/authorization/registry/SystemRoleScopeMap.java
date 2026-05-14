package org.cdpg.dx.auth.authorization.registry;

import java.util.EnumMap;
import java.util.Map;
import java.util.Set;
import org.cdpg.dx.auth.model.DxRole;
import org.cdpg.dx.auth.model.Scopes;

/**
 * Authoritative role → scope bundle for the five system roles. Code-level constant, never in the
 * database, so the dataplane needs no DB access to resolve authorization.
 */
public final class SystemRoleScopeMap {

  private static final Map<DxRole, Set<String>> MAP;

  static {
    EnumMap<DxRole, Set<String>> m = new EnumMap<>(DxRole.class);
    m.put(DxRole.CONSUMER, Set.of(Scopes.DATA_ACCESS));
    m.put(DxRole.PROVIDER, Set.of(Scopes.OWN_ASSET_MANAGEMENT));
    m.put(
        DxRole.ORG_ADMIN,
        Set.of(
            Scopes.ORG_USER_MANAGEMENT,
            Scopes.ORG_ASSET_MANAGEMENT,
            Scopes.ORG_ASSET_PUBLISH,
            Scopes.OWN_ASSET_MANAGEMENT,
            Scopes.ORG_PUBLISHER_MANAGEMENT));
    m.put(
        DxRole.COS_ADMIN,
        Set.of(
            Scopes.ORG_MANAGEMENT,
            Scopes.ASSET_PUBLISH,
            Scopes.ASSET_MANAGEMENT,
            Scopes.USER_MANAGEMENT,
            Scopes.PUBLISHER_MANAGEMENT,
            Scopes.ROLE_MANAGEMENT));
    m.put(DxRole.COMPUTE, Set.of(Scopes.COMPUTE_MANAGEMENT));
    MAP = Map.copyOf(m);
  }

  private SystemRoleScopeMap() {}

  /** Returns the scopes granted by this role. Empty set if the role is unmapped (defensive). */
  public static Set<String> getScopes(DxRole role) {
    return MAP.getOrDefault(role, Set.of());
  }
}