package org.cdpg.dx.auth.v2.registry;

import java.util.HashSet;
import java.util.Set;
import org.cdpg.dx.auth.v2.model.DxPrincipal;
import org.cdpg.dx.auth.v2.model.DxRole;

/**
 * In-memory implementation of {@link RoleScopeRegistry}.
 *
 * @deprecated See {@link RoleScopeRegistry} — scope resolution now happens at authentication time.
 *     Use {@link SystemRoleScopeMap} directly if role-to-scope flattening is needed.
 */
@Deprecated
public final class InMemoryRoleScopeRegistry implements RoleScopeRegistry {

  @Override
  public Set<String> resolveEffectiveScopes(DxPrincipal principal) {
    Set<String> effective = new HashSet<>();
    for (DxRole role : principal.getAuthorizationRoles()) {
      effective.addAll(SystemRoleScopeMap.getScopes(role));
    }
    effective.addAll(principal.getDirectScopes());
    return effective;
  }
}